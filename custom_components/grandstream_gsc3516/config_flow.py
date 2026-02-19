"""Config flow for Grandstream GSC3516."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .api import GrandstreamApiClient, GrandstreamApiError
from .const import (
    CONF_CALL_ACTIVE_VALUES,
    CONF_CALL_API_ACCOUNT,
    CONF_CALL_API_DIALPLAN,
    CONF_CALL_API_HS,
    CONF_CALL_API_PASSCODE,
    CONF_CALL_API_USE_PASSCODE,
    CONF_WEBHOOK_ID,
    CONF_WEBHOOK_PUSH_ENABLED,
    CONF_CALL_RINGING_VALUES,
    CONF_CALL_STATUS_KEY,
    CONF_DIAL_NUMBER_PVALUE,
    CONF_DIAL_TRIGGER_PVALUE,
    CONF_DIAL_TRIGGER_VALUE,
    CONF_HANGUP_PVALUE,
    CONF_HANGUP_VALUE,
    CONF_MUTE_FALSE_VALUE,
    CONF_MUTE_PVALUE,
    CONF_MUTE_TRUE_VALUE,
    CONF_SCAN_INTERVAL,
    CONF_SIP_REGISTERED_KEY,
    CONF_SIP_REGISTERED_ON_VALUES,
    CONF_STATUS_KEYS,
    CONF_USE_HTTPS,
    CONF_USE_CALL_API,
    CONF_API_SID,
    CONF_VERIFY_SSL,
    CONF_VOLUME_PVALUE,
    DEFAULT_CALL_ACTIVE_VALUES,
    DEFAULT_CALL_API_ACCOUNT,
    DEFAULT_CALL_API_DIALPLAN,
    DEFAULT_CALL_API_HS,
    DEFAULT_CALL_API_USE_PASSCODE,
    DEFAULT_WEBHOOK_ID,
    DEFAULT_WEBHOOK_PUSH_ENABLED,
    DEFAULT_CALL_RINGING_VALUES,
    DEFAULT_DIAL_TRIGGER_VALUE,
    DEFAULT_HANGUP_VALUE,
    DEFAULT_MUTE_FALSE_VALUE,
    DEFAULT_MUTE_TRUE_VALUE,
    DEFAULT_PORT_HTTP,
    DEFAULT_PORT_HTTPS,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SIP_REGISTERED_ON_VALUES,
    DEFAULT_STATUS_KEYS,
    DEFAULT_USE_HTTPS,
    DEFAULT_USE_CALL_API,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
)


STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_USE_HTTPS, default=DEFAULT_USE_HTTPS): bool,
        vol.Optional(CONF_PORT): int,
        vol.Optional(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): bool,
    }
)


class GrandstreamConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Grandstream GSC3516."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            user_input = dict(user_input)
            if not user_input.get(CONF_PORT):
                user_input[CONF_PORT] = (
                    DEFAULT_PORT_HTTPS if user_input[CONF_USE_HTTPS] else DEFAULT_PORT_HTTP
                )

            try:
                info = await self._async_validate_input(user_input)
            except GrandstreamApiError:
                errors["base"] = "cannot_connect"
            except Exception:
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(f"{user_input[CONF_HOST]}:{user_input[CONF_PORT]}")
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> "GrandstreamOptionsFlow":
        """Get the options flow for this handler."""
        return GrandstreamOptionsFlow(config_entry)

    async def _async_validate_input(self, data: dict[str, Any]) -> dict[str, Any]:
        """Validate that we can connect to the device."""
        session = async_create_clientsession(self.hass, verify_ssl=data[CONF_VERIFY_SSL])
        api = GrandstreamApiClient(
            host=data[CONF_HOST],
            port=data[CONF_PORT],
            username=data[CONF_USERNAME],
            password=data[CONF_PASSWORD],
            use_https=data[CONF_USE_HTTPS],
            session=session,
        )

        title = data[CONF_HOST]
        had_success = False

        # Try authenticated identity lookup first.
        try:
            await api.async_login()
            values = await api.async_get_values(["product_model", "vendor_fullname"])
            title = values.get("product_model") or title
            had_success = True
        except GrandstreamApiError:
            pass

        # Fallback for firmware that exposes status endpoints without login.
        if not had_success:
            try:
                await api.async_get_line_status()
                had_success = True
            except GrandstreamApiError:
                pass

        if not had_success:
            try:
                await api.async_get_phone_status()
                had_success = True
            except GrandstreamApiError:
                pass

        if not had_success:
            if await api.async_probe_http():
                had_success = True

        if not had_success:
            raise GrandstreamApiError("Cannot connect to any supported endpoint")

        return {"title": title}


class GrandstreamOptionsFlow(config_entries.OptionsFlow):
    """Handle options for Grandstream GSC3516."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Manage options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        defaults = {**self._config_entry.data, **self._config_entry.options}
        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_SCAN_INTERVAL,
                    default=defaults.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): vol.All(vol.Coerce(int), vol.Range(min=5, max=600)),
                vol.Optional(
                    CONF_STATUS_KEYS,
                    default=defaults.get(CONF_STATUS_KEYS, DEFAULT_STATUS_KEYS),
                ): str,
                vol.Optional(
                    CONF_VOLUME_PVALUE,
                    default=defaults.get(CONF_VOLUME_PVALUE, ""),
                ): str,
                vol.Optional(
                    CONF_MUTE_PVALUE,
                    default=defaults.get(CONF_MUTE_PVALUE, ""),
                ): str,
                vol.Optional(
                    CONF_MUTE_TRUE_VALUE,
                    default=defaults.get(CONF_MUTE_TRUE_VALUE, DEFAULT_MUTE_TRUE_VALUE),
                ): str,
                vol.Optional(
                    CONF_MUTE_FALSE_VALUE,
                    default=defaults.get(CONF_MUTE_FALSE_VALUE, DEFAULT_MUTE_FALSE_VALUE),
                ): str,
                vol.Optional(
                    CONF_SIP_REGISTERED_KEY,
                    default=defaults.get(CONF_SIP_REGISTERED_KEY, ""),
                ): str,
                vol.Optional(
                    CONF_SIP_REGISTERED_ON_VALUES,
                    default=defaults.get(
                        CONF_SIP_REGISTERED_ON_VALUES, DEFAULT_SIP_REGISTERED_ON_VALUES
                    ),
                ): str,
                vol.Optional(
                    CONF_CALL_STATUS_KEY,
                    default=defaults.get(CONF_CALL_STATUS_KEY, ""),
                ): str,
                vol.Optional(
                    CONF_CALL_ACTIVE_VALUES,
                    default=defaults.get(CONF_CALL_ACTIVE_VALUES, DEFAULT_CALL_ACTIVE_VALUES),
                ): str,
                vol.Optional(
                    CONF_CALL_RINGING_VALUES,
                    default=defaults.get(CONF_CALL_RINGING_VALUES, DEFAULT_CALL_RINGING_VALUES),
                ): str,
                vol.Optional(
                    CONF_DIAL_NUMBER_PVALUE,
                    default=defaults.get(CONF_DIAL_NUMBER_PVALUE, ""),
                ): str,
                vol.Optional(
                    CONF_USE_CALL_API,
                    default=defaults.get(CONF_USE_CALL_API, DEFAULT_USE_CALL_API),
                ): bool,
                vol.Optional(
                    CONF_CALL_API_ACCOUNT,
                    default=defaults.get(CONF_CALL_API_ACCOUNT, DEFAULT_CALL_API_ACCOUNT),
                ): vol.All(vol.Coerce(int), vol.Range(min=0, max=16)),
                vol.Optional(
                    CONF_CALL_API_DIALPLAN,
                    default=defaults.get(CONF_CALL_API_DIALPLAN, DEFAULT_CALL_API_DIALPLAN),
                ): str,
                vol.Optional(
                    CONF_CALL_API_USE_PASSCODE,
                    default=defaults.get(CONF_CALL_API_USE_PASSCODE, DEFAULT_CALL_API_USE_PASSCODE),
                ): bool,
                vol.Optional(
                    CONF_CALL_API_PASSCODE,
                    default=defaults.get(CONF_CALL_API_PASSCODE, ""),
                ): str,
                vol.Optional(
                    CONF_CALL_API_HS,
                    default=defaults.get(CONF_CALL_API_HS, DEFAULT_CALL_API_HS),
                ): bool,
                vol.Optional(
                    CONF_WEBHOOK_PUSH_ENABLED,
                    default=defaults.get(CONF_WEBHOOK_PUSH_ENABLED, DEFAULT_WEBHOOK_PUSH_ENABLED),
                ): bool,
                vol.Optional(
                    CONF_WEBHOOK_ID,
                    default=defaults.get(
                        CONF_WEBHOOK_ID,
                        DEFAULT_WEBHOOK_ID,
                    ),
                ): str,
                vol.Optional(
                    CONF_API_SID,
                    default=defaults.get(CONF_API_SID, ""),
                ): str,
                vol.Optional(
                    CONF_DIAL_TRIGGER_PVALUE,
                    default=defaults.get(CONF_DIAL_TRIGGER_PVALUE, ""),
                ): str,
                vol.Optional(
                    CONF_DIAL_TRIGGER_VALUE,
                    default=defaults.get(CONF_DIAL_TRIGGER_VALUE, DEFAULT_DIAL_TRIGGER_VALUE),
                ): str,
                vol.Optional(
                    CONF_HANGUP_PVALUE,
                    default=defaults.get(CONF_HANGUP_PVALUE, ""),
                ): str,
                vol.Optional(
                    CONF_HANGUP_VALUE,
                    default=defaults.get(CONF_HANGUP_VALUE, DEFAULT_HANGUP_VALUE),
                ): str,
            }
        )

        return self.async_show_form(step_id="init", data_schema=schema)
