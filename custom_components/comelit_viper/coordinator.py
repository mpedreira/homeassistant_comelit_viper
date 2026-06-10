"""Coordinator for Comelit VIPER."""
from __future__ import annotations

import logging
from typing import Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant

from .client import IconaBridgeClient, extract_door_config
from .const import CONF_TOKEN

_LOGGER = logging.getLogger(__name__)


class ComelitViperCoordinator:
    """
    Manages connection state and exposes the open_door action.

    The coordinator reconnects on every door-open call (matches the
    TypeScript CLI behaviour). The door configuration is fetched once
    and cached so subsequent presses skip the get-configuration step.
    """

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self.host: str = entry.data[CONF_HOST]
        self.port: int = entry.data[CONF_PORT]
        self.token: str = entry.data[CONF_TOKEN]
        self._door_config: Optional[dict] = None

    async def async_open_door(self) -> None:
        """Connect, authenticate, and open the door."""
        client = IconaBridgeClient(self.host, self.port)
        try:
            await client.connect()

            code = await client.authenticate(self.token)
            if code != 200:
                raise RuntimeError(f"Authentication failed (code={code})")

            if self._door_config is None:
                cfg = await client.get_config()
                if cfg is None:
                    raise RuntimeError("Failed to retrieve device configuration")
                self._door_config = extract_door_config(cfg)
                if self._door_config is None:
                    raise RuntimeError(
                        "No door found in device configuration. "
                        "Check that the intercom has entrance or opendoor entries."
                    )
                _LOGGER.info(
                    "Door config cached: %s", self._door_config
                )

            await client.open_door(**self._door_config)
            _LOGGER.info("Door opened successfully")

        except Exception:
            # Invalidate cached config so next press re-fetches it
            self._door_config = None
            raise
        finally:
            await client.disconnect()
