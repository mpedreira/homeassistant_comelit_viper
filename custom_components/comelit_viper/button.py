"""Button platform for Comelit VIPER — door unlock."""
from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import ComelitViperCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    _hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Comelit VIPER button entities."""
    coordinator: ComelitViperCoordinator = entry.runtime_data
    async_add_entities([ComelitDoorButton(coordinator, entry)])


class ComelitDoorButton(ButtonEntity):
    """Button that triggers the door-open sequence on the Comelit intercom."""

    _attr_has_entity_name = True
    _attr_translation_key = "open_door"
    _attr_icon = "mdi:door-open"

    def __init__(
        self, coordinator: ComelitViperCoordinator, entry: ConfigEntry
    ) -> None:
        self._coordinator = coordinator
        self._attr_unique_id = f"{entry.entry_id}_open_door"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=f"Comelit {coordinator.host}",
            manufacturer="Comelit",
            model="VIPER Video Intercom",
        )

    async def async_press(self) -> None:
        """Handle button press — open the door."""
        try:
            await self._coordinator.async_open_door()
        except Exception as exc:
            raise HomeAssistantError(
                f"Failed to open door: {exc}"
            ) from exc
