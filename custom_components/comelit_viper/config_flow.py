"""Config flow for Comelit VIPER."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_PORT

from .const import CONF_TOKEN, DEFAULT_PORT, DOMAIN
from .client import IconaBridgeClient

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_TOKEN): str,
    }
)


class ComelitViperConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Comelit VIPER."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            host: str = user_input[CONF_HOST]
            port: int = user_input[CONF_PORT]
            token: str = user_input[CONF_TOKEN]

            await self.async_set_unique_id(f"{host}:{port}")
            self._abort_if_unique_id_configured()

            client = IconaBridgeClient(host, port)
            try:
                await client.connect()
                code = await client.authenticate(token)
                if code == 200:
                    return self.async_create_entry(
                        title=f"Comelit {host}",
                        data=user_input,
                    )
                errors["base"] = "invalid_auth"
            except OSError:
                _LOGGER.exception("Error connecting to %s:%d", host, port)
                errors["base"] = "cannot_connect"
            finally:
                await client.disconnect()

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_SCHEMA,
            errors=errors,
        )
