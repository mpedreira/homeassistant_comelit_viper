"""
Comelit VIPER asyncio client.
Port of madchicken/comelit-client (TypeScript) icona-bridge-client.ts

Protocol overview (TCP port 64100):
  Frame header: 00 06 [body_len LE2] [req_id LE2] 00 00   (8 bytes)
  Channel open/close frames: req_id=0 in header; req_id is embedded inside body
  JSON/binary frames: req_id != 0 in header

Channel open (createBinaryPacketFromStrings):
  body = [COMMAND LE2][seq LE2] | [info LE4][channel_bytes][req_id LE2][0x00][0x00] | optional([info2 LE4][extra_data][0x00][0x00])

Channel close (createBinaryPacketFromStrings with no strings):
  body = [END LE2][seq LE2]

Binary door packets (createBinaryPacketFromBuffers):
  req_id in header; body = raw buffers concatenated
"""

import asyncio
import json
import logging
import struct
from typing import Optional

_LOGGER = logging.getLogger(__name__)

ICONA_BRIDGE_PORT = 64100
_HEADER_MAGIC = bytes([0x00, 0x06])
_NULL = bytes([0x00])
_MSG_COMMAND = 0xabcd
_MSG_END = 0x01ef


def _str_buf(s: str, null_terminated: bool = False) -> bytes:
    """Convert ASCII string to bytes, optionally null-terminated."""
    b = s.encode("ascii")
    return b + _NULL if null_terminated else b


def extract_door_config(config: dict) -> Optional[dict]:
    """
    Extract door parameters from a get-configuration response.

    Returns a dict with keys:
        vip_apt, vip_sub, door_apt, output_index
    or None if no door found.

    Tries opendoor-address-book first; falls back to
    entrance-address-book + opendoor-actions (e.g. Comelit MnWi).
    """
    vip = config.get("vip", {})
    vip_apt: str = vip.get("apt-address", "")
    vip_sub: int = vip.get("apt-subaddress", 0)
    params: dict = vip.get("user-parameters", {})

    # Primary source
    opendoor_book: list = params.get("opendoor-address-book", [])
    if opendoor_book:
        door = opendoor_book[0]
        return {
            "vip_apt": vip_apt,
            "vip_sub": vip_sub,
            "door_apt": door["apt-address"],
            "output_index": door["output-index"],
            "name": door.get("name", "Door"),
        }

    # Fallback: entrance-address-book + opendoor-actions
    entrance_book: list = params.get("entrance-address-book", [])
    opendoor_actions: list = params.get("opendoor-actions", [])
    if entrance_book and opendoor_actions:
        return {
            "vip_apt": vip_apt,
            "vip_sub": vip_sub,
            "door_apt": entrance_book[0]["apt-address"],
            "output_index": opendoor_actions[0].get("output-index", 1),
            "name": entrance_book[0].get("name", "Door"),
        }

    _LOGGER.error("No door configuration found in response")
    return None


class IconaBridgeClient:
    """
    Async TCP client for the Comelit VIPER / ICONA bridge protocol.

    Typical usage:
        client = IconaBridgeClient("192.168.1.X")
        await client.connect()
        code = await client.authenticate("your-token")
        if code == 200:
            cfg = await client.get_config()
            door = extract_door_config(cfg)
            await client.open_door(**door)
        await client.disconnect()
    """

    def __init__(self, host: str, port: int = ICONA_BRIDGE_PORT) -> None:
        self._host = host
        self._port = port
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._req_id: int = 8000  # start at 8000 like the TypeScript reference

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self._host, self._port),
            timeout=5.0,
        )
        _LOGGER.debug("Connected to %s:%d", self._host, self._port)

    async def disconnect(self) -> None:
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except OSError:
                pass
        self._reader = None
        self._writer = None
        _LOGGER.debug("Disconnected")

    # ------------------------------------------------------------------
    # Low-level framing helpers
    # ------------------------------------------------------------------

    def _next_req_id(self) -> int:
        self._req_id += 1
        return self._req_id

    def _frame_header(self, body_len: int, req_id: int) -> bytes:
        """8-byte frame header: 00 06 [body_len LE2] [req_id LE2] 00 00"""
        return (
            _HEADER_MAGIC
            + struct.pack("<H", body_len)
            + struct.pack("<H", req_id)
            + bytes([0x00, 0x00])
        )

    def _make_channel_open_packet(
        self, req_id: int, channel: str, additional_data: Optional[str] = None
    ) -> bytes:
        """
        Build a channel-OPEN (COMMAND) packet.

        Mirrors createBinaryPacketFromStrings(req_id, seq=1, COMMAND, channel, additional_data).
        req_id is NOT placed in the header; it is embedded inside the channel-name message.
        """
        # magicNumber: [COMMAND LE2][seq=1 LE2]
        magic = struct.pack("<HH", _MSG_COMMAND, 1)

        # First string message (channel name) embeds req_id
        ch = channel.encode("ascii")
        id_bytes = struct.pack("<H", req_id)
        # content = channel_bytes + req_id(2) + null(1)
        content1 = ch + id_bytes + _NULL
        info1 = struct.pack("<I", len(ch) + 2 + 1)  # len + id(2) + null(1)

        if additional_data is not None:
            # When a second message follows, msg1 needs a trailing null as separator
            msg1 = info1 + content1 + _NULL
            ad = additional_data.encode("ascii")
            info2 = struct.pack("<I", len(ad) + 1)
            msg2 = info2 + ad + _NULL  # info + data + null terminator (no extra null)
            body = magic + msg1 + msg2
        else:
            # No additional message: no trailing null after content1
            msg1 = info1 + content1
            body = magic + msg1

        # Header: req_id = 0 (createBinaryPacketFromStrings does not set it)
        return (
            _HEADER_MAGIC
            + struct.pack("<H", len(body))
            + bytes([0x00, 0x00, 0x00, 0x00])
            + body
        )

    def _make_channel_close_packet(self, seq: int) -> bytes:
        """
        Build a channel-CLOSE (END) packet with given sequence number.

        Mirrors createBinaryPacketFromStrings(id, seq, END) with no string messages.
        """
        body = struct.pack("<HH", _MSG_END, seq)
        return (
            _HEADER_MAGIC
            + struct.pack("<H", len(body))
            + bytes([0x00, 0x00, 0x00, 0x00])
            + body
        )

    def _make_json_packet(self, req_id: int, data: dict) -> bytes:
        """Build a JSON packet. Mirrors createJSONPacket."""
        body = json.dumps(data, separators=(",", ":")).encode("ascii")
        return self._frame_header(len(body), req_id) + body

    def _make_binary_packet(self, req_id: int, *buffers: bytes) -> bytes:
        """Build a binary door packet. Mirrors createBinaryPacketFromBuffers."""
        body = b"".join(buffers)
        return self._frame_header(len(body), req_id) + body

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    async def _write(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def _read_response(
        self, timeout: float = 5.0, silent: bool = False
    ) -> Optional[dict]:
        """Read one frame from the server and decode it."""
        try:
            header = await asyncio.wait_for(
                self._reader.readexactly(8), timeout=timeout
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError) as exc:
            if silent:
                _LOGGER.debug("Read header (optional): %s", exc)
            else:
                _LOGGER.warning("Read header error: %s", exc)
            return None

        body_len = struct.unpack_from("<H", header, 2)[0]
        # bytes 4-7: req_id (read as 4 bytes LE; high 2 bytes are usually 0)
        req_id = struct.unpack_from("<I", header, 4)[0]

        body = b""
        if body_len > 0:
            try:
                body = await asyncio.wait_for(
                    self._reader.readexactly(body_len), timeout=timeout
                )
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError) as exc:
                _LOGGER.warning("Read body error: %s", exc)
                return None

        return self._decode_response(req_id, body)

    def _decode_response(self, req_id: int, body: bytes) -> dict:
        """
        Decode a server frame.

        req_id == 0  → binary channel response (COMMAND/END); body starts with [type LE2][seq LE2]
        req_id != 0 and body[0] == '{' → JSON response
        req_id != 0 otherwise → binary door ack
        """
        if req_id == 0:
            if len(body) < 4:
                return {"type": "binary", "msg_type": 0, "seq": 0}
            msg_type = struct.unpack_from("<H", body, 0)[0]
            seq = struct.unpack_from("<H", body, 2)[0]
            return {"type": "binary", "msg_type": msg_type, "seq": seq}

        if body and body[0] == 0x7B:  # ASCII '{'
            try:
                return {
                    "type": "json",
                    "req_id": req_id,
                    "data": json.loads(body.decode("utf-8")),
                }
            except json.JSONDecodeError as exc:
                _LOGGER.warning("JSON decode error: %s", exc)

        # Binary door ack (type byte at body[1])
        return {"type": "binary_ack", "req_id": req_id}

    # ------------------------------------------------------------------
    # Channel management
    # ------------------------------------------------------------------

    async def _open_channel(
        self, channel: str, additional_data: Optional[str] = None
    ) -> int:
        """
        Open a protocol channel.

        Returns the req_id assigned to this channel.
        Raises RuntimeError if the server doesn't confirm.
        """
        req_id = self._next_req_id()
        pkt = self._make_channel_open_packet(req_id, channel, additional_data)
        await self._write(pkt)
        resp = await self._read_response()
        if resp and resp.get("type") == "binary" and resp.get("seq") == 2:
            _LOGGER.debug("Channel %s opened (req_id=%d)", channel, req_id)
            return req_id
        raise RuntimeError(
            f"Failed to open channel {channel}: unexpected response {resp}"
        )

    async def _close_channel(self, current_seq: int) -> None:
        """
        Close the currently active channel.

        current_seq is 2 after a fresh channel open.
        Sends END with seq=current_seq+1 and expects seq=current_seq+2 back.
        """
        close_seq = current_seq + 1
        pkt = self._make_channel_close_packet(close_seq)
        await self._write(pkt)
        resp = await self._read_response()
        expected = close_seq + 1
        if resp and resp.get("seq") == expected:
            _LOGGER.debug("Channel closed (seq=%d)", close_seq)
        else:
            _LOGGER.warning(
                "Unexpected close response: %s (expected seq=%d)", resp, expected
            )

    # ------------------------------------------------------------------
    # High-level operations
    # ------------------------------------------------------------------

    async def authenticate(self, token: str) -> int:
        """
        Authenticate with the device using a user token.

        Returns response-code (200 = success).
        """
        req_id = await self._open_channel("UAUT")
        msg = {
            "message": "access",
            "user-token": token,
            "message-type": "request",
            "message-id": 2,  # ViperChannelType.UAUT
        }
        await self._write(self._make_json_packet(req_id, msg))
        resp = await self._read_response()
        if resp and resp.get("type") == "json":
            code: int = resp["data"].get("response-code", 500)
            await self._close_channel(current_seq=2)
            _LOGGER.debug("Auth response code: %d", code)
            return code
        _LOGGER.error("Auth: unexpected response: %s", resp)
        return 500

    async def get_config(self) -> Optional[dict]:
        """
        Request full device configuration (addressbooks=all).

        Returns the parsed JSON response dict, or None on error.
        """
        req_id = await self._open_channel("UCFG")
        msg = {
            "message": "get-configuration",
            "addressbooks": "all",
            "message-type": "request",
            "message-id": 3,  # ViperChannelType.UCFG
        }
        await self._write(self._make_json_packet(req_id, msg))
        resp = await self._read_response()
        if resp and resp.get("type") == "json":
            await self._close_channel(current_seq=2)
            return resp["data"]
        _LOGGER.error("get_config: unexpected response: %s", resp)
        return None

    # ------------------------------------------------------------------
    # Binary door message builders
    # ------------------------------------------------------------------

    def _unknown_open_door_msg(
        self, req_id: int, vip_apt: str, vip_sub: int
    ) -> bytes:
        """
        CTPP channel init message (getUnknownOpenDoorMessage in TypeScript).
        Sent once after opening the CTPP channel.
        """
        apt_sub = f"{vip_apt}{vip_sub}"
        return self._make_binary_packet(
            req_id,
            bytes([0xC0, 0x18, 0x5C, 0x8B]),
            bytes([0x2B, 0x73, 0x00, 0x11]),
            bytes([0x00, 0x40, 0xAC, 0x23]),
            _str_buf(apt_sub, null_terminated=True),
            bytes([0x10, 0x0E]),
            bytes([0x00, 0x00, 0x00, 0x00]),
            bytes([0xFF, 0xFF, 0xFF, 0xFF]),
            _str_buf(apt_sub, null_terminated=True),
            _str_buf(vip_apt, null_terminated=True),
            _NULL,
        )

    def _open_door_msg(
        self,
        req_id: int,
        vip_apt: str,
        door_apt: str,
        output_index: int,
        confirm: bool = False,
    ) -> bytes:
        """
        Door-open trigger message (getOpenDoorMessage in TypeScript).

        confirm=False → first byte 0x00 (OPEN_DOOR low byte = 0x1800 & 0xFF)
        confirm=True  → first byte 0x20 (OPEN_DOOR_CONFIRM low byte = 0x1820 & 0xFF)
        """
        return self._make_binary_packet(
            req_id,
            bytes([0x20 if confirm else 0x00]),
            bytes([0x5C, 0x8B]),
            bytes([0x2C, 0x74, 0x00, 0x00]),
            bytes([0xFF, 0xFF, 0xFF, 0xFF]),
            _str_buf(f"{vip_apt}{output_index}", null_terminated=True),
            _str_buf(door_apt),  # no null terminator here; explicit NULL follows
            _NULL,
        )

    def _init_open_door_msg(
        self,
        req_id: int,
        vip_apt: str,
        door_apt: str,
        output_index: int,
    ) -> bytes:
        """
        Door-open init message (getInitOpenDoorMessage in TypeScript).
        """
        return self._make_binary_packet(
            req_id,
            bytes([0xC0, 0x18, 0x70, 0xAB]),
            bytes([0x29, 0x9F, 0x00, 0x0D]),
            bytes([0x00, 0x2D]),
            _str_buf(door_apt, null_terminated=True),
            _NULL,
            bytes([output_index, 0x00, 0x00, 0x00]),
            bytes([0xFF, 0xFF, 0xFF, 0xFF]),
            _str_buf(f"{vip_apt}{output_index}", null_terminated=True),
            _str_buf(door_apt, null_terminated=True),
            _NULL,
        )

    # ------------------------------------------------------------------
    # Door open
    # ------------------------------------------------------------------

    async def open_door(
        self,
        vip_apt: str,
        vip_sub: int,
        door_apt: str,
        output_index: int,
        **_kwargs,
    ) -> None:
        """
        Open a door using the CTPP binary protocol.

        This is a direct port of IconaBridgeClient.openDoor() +
        openDoorInit() from icona-bridge-client.ts.

        Sequence:
          1. Open CTPP channel with additionalData = vip_apt + str(vip_sub)
          2. Send CTPP init message, read 2 responses
          3. Send open_door (false) + open_door (true)
          4. Send init_open_door
          5. Read 2 responses
          6. Send open_door (false) + open_door (true)  [fire-and-forget]
          7. Disconnect (channel not explicitly closed, like the TS reference)
        """
        additional = f"{vip_apt}{vip_sub}"
        ctpp_id = await self._open_channel("CTPP", additional)

        # Step 2: CTPP init
        await self._write(self._unknown_open_door_msg(ctpp_id, vip_apt, vip_sub))
        await self._read_response(timeout=2.0, silent=True)
        await self._read_response(timeout=2.0, silent=True)

        # Steps 3-4
        await self._write(
            self._open_door_msg(ctpp_id, vip_apt, door_apt, output_index, confirm=False)
        )
        await self._write(
            self._open_door_msg(ctpp_id, vip_apt, door_apt, output_index, confirm=True)
        )
        await self._write(
            self._init_open_door_msg(ctpp_id, vip_apt, door_apt, output_index)
        )

        # Step 5
        await self._read_response(timeout=2.0, silent=True)
        await self._read_response(timeout=2.0, silent=True)

        # Steps 6: final open + confirm (fire-and-forget, no read)
        await self._write(
            self._open_door_msg(ctpp_id, vip_apt, door_apt, output_index, confirm=False)
        )
        await self._write(
            self._open_door_msg(ctpp_id, vip_apt, door_apt, output_index, confirm=True)
        )

        _LOGGER.info(
            "Door open sequence sent (door_apt=%s output_index=%d)",
            door_apt,
            output_index,
        )
        # Do NOT close CTPP channel explicitly (matches TypeScript reference behaviour)
