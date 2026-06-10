"""
Standalone test — run from the repo root:

    python test_client.py

Connects to the Comelit MnWi, authenticates, fetches the door config,
and opens the door. Edit HOST and TOKEN if needed.
"""

import asyncio
import logging
import sys

# Add the custom_components package to path so client.py is importable
sys.path.insert(0, __file__.rsplit("\\", 1)[0])

from custom_components.comelit_viper.client import (
    IconaBridgeClient,
    extract_door_config,
)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)

HOST = "10.168.168.44"
PORT = 64100
TOKEN = "3f81d40514486669fb62a43455676261"


async def main() -> None:
    client = IconaBridgeClient(HOST, PORT)
    try:
        print(f"Connecting to {HOST}:{PORT} …")
        await client.connect()

        print("Authenticating …")
        code = await client.authenticate(TOKEN)
        print(f"Auth response code: {code}")
        if code != 200:
            print("Authentication failed — check TOKEN")
            return

        print("Fetching configuration …")
        cfg = await client.get_config()
        if cfg is None:
            print("get_config returned None")
            return

        door = extract_door_config(cfg)
        if door is None:
            print("No door found in config")
            return

        print(f"Door config: {door}")

        answer = input("Open door now? [y/N] ").strip().lower()
        if answer == "y":
            print("Opening door …")
            await client.open_door(**door)
            print("Door open sequence sent.")
        else:
            print("Skipped.")

    finally:
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
