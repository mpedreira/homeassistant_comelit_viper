#!/usr/bin/env python3
"""
Comelit VIPER snapshot capture.

Connects to the device during an ACTIVE doorbell call (someone ringing)
and captures one JPEG frame from the entrance camera.

REQUIREMENTS:
  - ffmpeg installed and on PATH  (apt install ffmpeg)
  - Someone MUST be pressing the doorbell when this script starts
  - Run within ~30 seconds of the doorbell event

USAGE:
  python3 snapshot.py                         # wait 30s for a call
  python3 snapshot.py --timeout 5             # wait 5s (for testing)
  python3 snapshot.py --debug                 # verbose logging

PROTOCOL NOTES (from Wireshark capture data.txt analysis):
  The device runs the Comelit VIPER protocol on TCP port 64100.
  Frame format: 8-byte header [00 06 <len LE2> <req_id LE4>] + body.

  Call sequence (from capture):
    1. Auth on UAUT channel (JSON)
    2. Open CTPP channel with apt+sub as additionalData
    3. Send CTPP init: C0 18 3E 06 ... (probes call state)
    4. Device responds C0 18 03 07 ... (active call notification)
    5. Open UDPM06 channel
    6. Send call-answer: 40 18 03 07 [session+1] ...
    7. (optional further exchange — device may send 00 18 83 07 responses)
    8. Open RTPC16 (audio) + RTPC26 (video) channels
    9. Send audio setup on CTPP (channel "16")
   10. Send video setup on CTPP (channel "26")
   11. Collect RTP/H.264 frames (req_id == 0x3632 = ASCII "26" LE)
   12. Pipe to ffmpeg -> JPEG

  RTPC26 video frames have VIPER req_id = 0x3632 (ASCII bytes of "26" LE).
  RTP header: V=2 (0x80), PT=99 (dynamic H.264), RFC 6184 encapsulation.
"""

import asyncio
import argparse
import json
import logging
import struct
import subprocess
import sys
import io
from typing import Optional, Tuple

log = logging.getLogger("comelit_snapshot")

# ---- device defaults (edit to match your setup) --------------------------
DEFAULT_HOST  = "10.168.168.44"
DEFAULT_PORT  = 64100
DEFAULT_TOKEN = "3f81d40514486669fb62a43455676261"
DEFAULT_OUT   = "/tmp/doorbell.jpg"
VIP_APT  = "00000003"
VIP_SUB  = 5
DOOR_APT = "00000100"
# --------------------------------------------------------------------------

NULL = b"\x00"
VIPER_MAGIC = b"\x00\x06"

# req_id that the device uses for RTPC26 video frames:
# ASCII bytes of "26" interpreted as LE uint32 = 0x00003632
RTPC26_RID = struct.unpack("<I", b"26\x00\x00")[0]
RTPC16_RID = struct.unpack("<I", b"16\x00\x00")[0]


def _s(s: str, null_term: bool = False) -> bytes:
    b = s.encode("ascii")
    return b + NULL if null_term else b


def _make_hdr(body_len: int, req_id: int) -> bytes:
    return VIPER_MAGIC + struct.pack("<H", body_len) + struct.pack("<I", req_id)


def _binary(req_id: int, *bufs: bytes) -> bytes:
    body = b"".join(bufs)
    return _make_hdr(len(body), req_id) + body


def _json_pkt(req_id: int, data: dict) -> bytes:
    body = json.dumps(data, separators=(",", ":")).encode("ascii")
    return _make_hdr(len(body), req_id) + body


def _ch_open(req_id: int, channel: str, additional: Optional[str] = None) -> bytes:
    """
    Build a VIPER channel-open packet (outer req_id = 0).
    Format from capture: magic(ABCD 0001) + info1_len(LE4) + channel_name + 0x01
    Optionally followed by info2_len(LE4) + additional_data + 0x00 + 0x00.
    """
    ch = channel.encode("ascii")
    content1 = ch + b"\x01"                    # channel name + version byte
    info1 = struct.pack("<I", len(content1))
    body = struct.pack("<HH", 0xABCD, 1) + info1 + content1
    if additional is not None:
        ad = additional.encode("ascii")
        info2 = struct.pack("<I", len(ad) + 1)
        body += info2 + ad + NULL + NULL
    return VIPER_MAGIC + struct.pack("<H", len(body)) + b"\x00\x00\x00\x00" + body


def _ch_close(seq: int) -> bytes:
    body = struct.pack("<HH", 0x01EF, seq)
    return VIPER_MAGIC + struct.pack("<H", len(body)) + b"\x00\x00\x00\x00" + body


async def _read(reader: asyncio.StreamReader, timeout: float = 10.0) -> Optional[Tuple[int, bytes]]:
    """Read one VIPER frame. Returns (req_id, body) or None on timeout/error."""
    try:
        header = await asyncio.wait_for(reader.readexactly(8), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError):
        return None
    body_len = struct.unpack_from("<H", header, 2)[0]
    req_id   = struct.unpack_from("<I", header, 4)[0]
    if body_len == 0:
        return req_id, b""
    try:
        body = await asyncio.wait_for(reader.readexactly(body_len), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError):
        return None
    return req_id, body


# --------------------------------------------------------------------------
# H.264 / RTP helpers
# --------------------------------------------------------------------------

def extract_h264_from_rtp(rtp: bytes) -> bytes:
    """
    Strip 12-byte fixed RTP header and convert H.264 payload to Annex-B format
    per RFC 6184. Handles single NAL (1-23), STAP-A (24), FU-A (28).
    """
    if len(rtp) < 13:
        return b""
    # Skip optional CSRC list (CC field in RTP header byte 0, bits 3:0)
    cc = rtp[0] & 0x0F
    hdr_len = 12 + cc * 4
    if len(rtp) <= hdr_len:
        return b""
    payload  = rtp[hdr_len:]
    nal_type = payload[0] & 0x1F

    if 1 <= nal_type <= 23:
        return b"\x00\x00\x00\x01" + payload

    if nal_type == 24:          # STAP-A
        result, i = b"", 1
        while i + 1 < len(payload):
            size = struct.unpack_from(">H", payload, i)[0]
            i += 2
            if i + size > len(payload):
                break
            result += b"\x00\x00\x00\x01" + payload[i : i + size]
            i += size
        return result

    if nal_type == 28:          # FU-A
        if len(payload) < 3:
            return b""
        fu_hdr  = payload[1]
        start   = (fu_hdr >> 7) & 1
        nal_hdr = (payload[0] & 0xE0) | (fu_hdr & 0x1F)
        if start:
            return b"\x00\x00\x00\x01" + bytes([nal_hdr]) + payload[2:]
        return payload[2:]      # continuation — no start code

    return b""


def is_keyframe(rtp: bytes) -> bool:
    """True if the RTP packet contains SPS (7), PPS (8), or IDR (5) NAL."""
    if len(rtp) < 13:
        return False
    payload  = rtp[12:]
    nal_type = payload[0] & 0x1F
    if nal_type in (5, 7, 8):
        return True
    if nal_type == 24 and len(payload) >= 4:
        return (payload[3] & 0x1F) in (5, 7, 8)
    if nal_type == 28 and len(payload) >= 2:
        return ((payload[1] >> 7) & 1) and ((payload[1] & 0x1F) in (5, 7, 8))
    return False


# --------------------------------------------------------------------------
# Main capture logic
# --------------------------------------------------------------------------

async def capture_snapshot(
    host:            str,
    port:            int,
    token:           str,
    output:          str,
    vip_apt:         str   = VIP_APT,
    vip_sub:         int   = VIP_SUB,
    door_apt:        str   = DOOR_APT,
    call_timeout:    float = 30.0,
    video_collect_s: float = 4.0,
) -> bool:

    apt_sub = vip_apt + str(vip_sub)   # "000000035"

    log.info("Connecting to %s:%d ...", host, port)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=5.0
        )
    except (asyncio.TimeoutError, OSError) as exc:
        log.error("Connection failed: %s", exc)
        return False

    req_id = 8000

    async def write(*pkts: bytes) -> None:
        for p in pkts:
            writer.write(p)
        await writer.drain()

    try:
        # ------------------------------------------------------------------ #
        # 1. Authenticate on UAUT channel
        # ------------------------------------------------------------------ #
        req_id += 1; uaut_id = req_id
        await write(_ch_open(uaut_id, "UAUT"))
        await _read(reader)          # channel-open ACK
        await write(_json_pkt(uaut_id, {
            "message": "access",
            "user-token": token,
            "message-type": "request",
            "message-id": 2,
        }))
        resp = await _read(reader)
        if not resp or not resp[1] or resp[1][0] != 0x7B:
            log.error("Auth: unexpected response")
            return False
        code = json.loads(resp[1]).get("response-code", 0)
        if code != 200:
            log.error("Auth failed, response-code=%d", code)
            return False
        await write(_ch_close(3))
        await _read(reader); await _read(reader)
        log.info("Authenticated OK")

        # ------------------------------------------------------------------ #
        # 2. Open CTPP channel and send init probe
        # ------------------------------------------------------------------ #
        req_id += 1; ctpp_id = req_id
        await write(_ch_open(ctpp_id, "CTPP", apt_sub))
        await _read(reader)          # CTPP channel ACK

        # Send CTPP init — probes the device for current call state.
        # Magic bytes from capture; device is lenient about session bytes.
        ctpp_init = _binary(
            ctpp_id,
            bytes([0xC0, 0x18, 0x3E, 0x06]),
            bytes([0xF7, 0x2A, 0x00, 0x11]),
            bytes([0x00, 0x40, 0x06, 0xA2]),
            _s(apt_sub, True),
            bytes([0x10, 0x0E, 0x00, 0x00, 0x00, 0x00]),
            bytes([0xFF, 0xFF, 0xFF, 0xFF]),
            _s(apt_sub, True),
            _s(vip_apt, True),
            NULL,
        )
        await write(ctpp_init)

        # ------------------------------------------------------------------ #
        # 3. Wait for ACTIVE call notification C0 18 from device
        # ------------------------------------------------------------------ #
        # The device sends C0 18 03 07 ... when someone is at the door.
        # It also sends 00 18 / 40 18 frames as state pings — we skip those.
        log.info("Waiting for active call (door bell must be ringing)... timeout=%.0fs", call_timeout)
        call_body  = None
        deadline   = asyncio.get_event_loop().time() + call_timeout
        while asyncio.get_event_loop().time() < deadline:
            frame = await _read(reader, timeout=2.0)
            if not frame:
                log.debug("No frame (timeout), retrying...")
                continue
            rid, body = frame
            if len(body) < 2:
                continue
            if body[1] != 0x18:
                log.debug("Frame rid=0x%x body[0]=0x%02x (not 0x18), skip", rid, body[0])
                continue
            if body[0] == 0x00:
                log.debug("Idle-state frame (0x00 0x18), no active call yet")
                continue
            # 0x40, 0x60, or 0xC0 with 0x18 = active call
            log.info("Active call notification (type=0x%02X 0x18)", body[0])
            call_body = body
            break

        if call_body is None:
            log.error(
                "No active call detected in %.0fs. "
                "Make sure someone is pressing the doorbell when you run this script.",
                call_timeout,
            )
            return False

        # Extract session counter from call notification bytes [4:6]
        call_session = struct.unpack_from("<H", call_body, 4)[0]
        log.debug("Call session counter: 0x%04X", call_session)

        # ------------------------------------------------------------------ #
        # 4. Open UDPM06 channel (seen in capture right after C0 18 notify)
        # ------------------------------------------------------------------ #
        req_id += 1; udpm_id = req_id
        await write(_ch_open(udpm_id, "UDPM06"))
        await _read(reader, timeout=1.0)    # ACK (may contain UDP port info)

        # ------------------------------------------------------------------ #
        # 5. Send call-answer (40 18 03 07 format, with session counter + 1)
        # ------------------------------------------------------------------ #
        # Format from Wireshark capture (lines 381-383 in data.txt):
        #   40 18 03 07 [sess+1 LE2] 00 08 00 03 49 00 27 00 00 00
        #   ff ff ff ff [apt_sub\0] [door_apt\0\0]
        ans_session = (call_session + 1) & 0xFFFF
        call_answer = _binary(
            ctpp_id,
            bytes([0x40, 0x18, 0x03, 0x07]),
            struct.pack("<H", ans_session),
            bytes([0x00, 0x08, 0x00, 0x03]),
            bytes([0x49, 0x00]),         # 'I' marker from capture
            bytes([0x27, 0x00, 0x00, 0x00]),
            bytes([0xFF, 0xFF, 0xFF, 0xFF]),
            _s(apt_sub, True),
            _s(door_apt, True),
            NULL,
        )
        await write(call_answer)
        log.info("Call-answer sent")

        # Drain device state responses (00 18 / 40 18 pings) for ~1 second
        t0 = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - t0 < 1.0:
            frame = await _read(reader, timeout=0.4)
            if not frame:
                break
            rid, body = frame
            log.debug("Post-answer frame rid=0x%x len=%d body[:4]=%s",
                      rid, len(body), body[:4].hex() if body else "")

        # ------------------------------------------------------------------ #
        # 6. Open RTPC16 (audio) + RTPC26 (video) channels
        # ------------------------------------------------------------------ #
        req_id += 1; rtpc16_id = req_id
        req_id += 1; rtpc26_id = req_id
        # Send both opens together as the app does in the capture
        await write(
            _ch_open(rtpc16_id, "RTPC16"),
            _ch_open(rtpc26_id, "RTPC26"),
        )
        # Drain channel ACKs
        for _ in range(4):
            frame = await _read(reader, timeout=0.5)
            if not frame:
                break

        # ------------------------------------------------------------------ #
        # 7. Send audio setup on CTPP (channel "16")
        # ------------------------------------------------------------------ #
        # From capture (offset 0x30 in lines 404-411):
        #   40 18 03 07 [sess] 00 0a 00 11 18 02 00 00 00 00
        #   31 36 00 00  ff ff ff ff  [apt_sub\0] [door_apt\0\0]
        audio_session = (ans_session + 1) & 0xFFFF
        audio_setup = _binary(
            ctpp_id,
            bytes([0x40, 0x18, 0x03, 0x07]),
            struct.pack("<H", audio_session),
            bytes([0x00, 0x0A, 0x00, 0x11]),
            bytes([0x18, 0x02, 0x00, 0x00, 0x00, 0x00]),
            b"16",                              # audio channel identifier
            bytes([0x00, 0x00]),
            bytes([0xFF, 0xFF, 0xFF, 0xFF]),
            _s(apt_sub, True),
            _s(door_apt, True),
            NULL,
        )

        # ------------------------------------------------------------------ #
        # 8. Send video setup on CTPP (channel "26")
        # ------------------------------------------------------------------ #
        # From capture (lines 422-427 in data.txt):
        #   40 18 03 07 [sess+1] 00 1a 00 11 14 32 00 00 00 00
        #   32 36  ff ff 00 00 00 00
        #   [w800 LE2] [h480 LE2] [w320 LE2] [h240 LE2] [16fps LE4]
        #   ff ff ff ff  [apt_sub\0] [door_apt\0\0]
        video_session = (audio_session + 1) & 0xFFFF
        video_setup = _binary(
            ctpp_id,
            bytes([0x40, 0x18, 0x03, 0x07]),
            struct.pack("<H", video_session),
            bytes([0x00, 0x1A, 0x00, 0x11]),
            bytes([0x14, 0x32, 0x00, 0x00, 0x00, 0x00]),
            b"26",                              # video channel identifier
            bytes([0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]),
            struct.pack("<H", 800),             # main width
            struct.pack("<H", 480),             # main height
            struct.pack("<H", 320),             # sub width
            struct.pack("<H", 240),             # sub height
            struct.pack("<I", 16),              # framerate
            bytes([0xFF, 0xFF, 0xFF, 0xFF]),
            _s(apt_sub, True),
            _s(door_apt, True),
            NULL,
        )

        await write(audio_setup, video_setup)
        log.info("Audio + video setup sent, collecting H.264 frames for %.1fs...", video_collect_s)

        # ------------------------------------------------------------------ #
        # 9. Collect RTP/H.264 frames
        # ------------------------------------------------------------------ #
        # Video frames have VIPER req_id = 0x3632 (= ASCII "26" as LE uint32).
        # RTP header: V=2 (byte 0x80), PT=99 (dynamic H.264).
        # Audio frames have req_id = 0x3631 (= "16") and PT=8 (G.711) -- skip.
        h264_buf  = io.BytesIO()
        n_video   = 0
        found_idr = False
        deadline2 = asyncio.get_event_loop().time() + video_collect_s

        while asyncio.get_event_loop().time() < deadline2:
            frame = await _read(reader, timeout=1.0)
            if not frame:
                continue
            rid, body = frame

            log.debug("rx rid=0x%08x len=%d first=%s",
                      rid, len(body), body[:4].hex() if body else "")

            # Short frames are control/ack frames, not RTP
            if len(body) < 12:
                continue
            # RTP version check: V=2 -> byte[0] must be 0x80 (or 0xA0 with padding)
            if (body[0] & 0xC0) != 0x80:
                continue
            pt = body[1] & 0x7F
            if pt == 8:        # G.711 audio (RTPC16) — skip
                continue

            h264 = extract_h264_from_rtp(body)
            if not h264:
                continue

            n_video += 1
            h264_buf.write(h264)
            if not found_idr and is_keyframe(body):
                found_idr = True
                log.info("Keyframe (IDR/SPS) found at packet %d", n_video)

        h264_bytes = h264_buf.getvalue()

        if not h264_bytes:
            log.error(
                "No H.264 video received after %.1fs. "
                "Either nobody rang the doorbell, or the call-answer "
                "handshake was not accepted by the device. "
                "Try running with --debug to see all received frames.",
                video_collect_s,
            )
            return False

        log.info("Collected %d video packets (%d bytes H.264), extracting JPEG...",
                 n_video, len(h264_bytes))

    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

    # ------------------------------------------------------------------ #
    # 10. Extract JPEG with ffmpeg
    # ------------------------------------------------------------------ #
    try:
        result = subprocess.run(
            ["ffmpeg", "-y", "-f", "h264", "-i", "pipe:0",
             "-frames:v", "1", "-q:v", "2", output],
            input=h264_bytes,
            capture_output=True,
            timeout=15,
        )
        if result.returncode != 0:
            log.error("ffmpeg failed:\n%s", result.stderr.decode(errors="replace"))
            return False
    except FileNotFoundError:
        log.error("ffmpeg not found. Install it: apt install ffmpeg")
        return False
    except subprocess.TimeoutExpired:
        log.error("ffmpeg timed out")
        return False

    log.info("Snapshot saved -> %s", output)
    return True


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Comelit VIPER camera snapshot — captures a JPEG during a live doorbell call",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host",    default=DEFAULT_HOST,  help="Device IP")
    parser.add_argument("--port",    default=DEFAULT_PORT,  type=int, help="TCP port (default 64100)")
    parser.add_argument("--token",   default=DEFAULT_TOKEN, help="Auth token")
    parser.add_argument("--output",  default=DEFAULT_OUT,   help="Output JPEG path")
    parser.add_argument("--timeout", default=30.0,          type=float,
                        help="Seconds to wait for an active doorbell call (default 30)")
    parser.add_argument("--collect", default=4.0,           type=float,
                        help="Seconds to collect H.264 frames (default 4)")
    parser.add_argument("--debug",   action="store_true",   help="Verbose frame logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
    )

    ok = await capture_snapshot(
        host=args.host, port=args.port, token=args.token,
        output=args.output, call_timeout=args.timeout,
        video_collect_s=args.collect,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
