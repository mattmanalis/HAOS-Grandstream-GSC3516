"""Data update coordinator for Grandstream GSC3516."""

from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import GrandstreamApiClient, GrandstreamApiError
from .const import (
    CONF_CALL_STATUS_KEY,
    CONF_MUTE_PVALUE,
    CONF_SCAN_INTERVAL,
    CONF_SIP_REGISTERED_KEY,
    CONF_STATUS_KEYS,
    CONF_VOLUME_PVALUE,
    COORDINATOR_KEY_ACCOUNTS,
    COORDINATOR_KEY_LINE_STATUS,
    COORDINATOR_KEY_ONLINE,
    COORDINATOR_KEY_PHONE_STATUS,
    COORDINATOR_KEY_STATUS,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_STATUS_KEYS,
)

_LOGGER = logging.getLogger(__name__)


class GrandstreamDataUpdateCoordinator(DataUpdateCoordinator[dict[str, object]]):
    """Coordinator for polling Grandstream speaker status."""

    config_entry: ConfigEntry

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, api: GrandstreamApiClient) -> None:
        self.api = api
        self.config_entry = entry

        interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            name=f"Grandstream GSC3516 {entry.data[CONF_HOST]}",
            update_interval=timedelta(seconds=interval),
        )

    async def _async_update_data(self) -> dict[str, object]:
        keys = _parse_status_keys(
            self.config_entry.options.get(CONF_STATUS_KEYS, DEFAULT_STATUS_KEYS)
        )

        volume_key = self.config_entry.options.get(CONF_VOLUME_PVALUE, "").strip()
        if volume_key and volume_key not in keys:
            keys.append(volume_key)
        mute_key = self.config_entry.options.get(CONF_MUTE_PVALUE, "").strip()
        if mute_key and mute_key not in keys:
            keys.append(mute_key)
        sip_key = self.config_entry.options.get(CONF_SIP_REGISTERED_KEY, "").strip()
        if sip_key and sip_key not in keys:
            keys.append(sip_key)
        call_key = self.config_entry.options.get(CONF_CALL_STATUS_KEY, "").strip()
        if call_key and call_key not in keys:
            keys.append(call_key)

        try:
            await self.api.async_login()
            status = await self.api.async_get_values(keys)
            line_status = await self.api.async_get_line_status()
            phone_status = await self.api.async_get_phone_status()
            accounts = await self.api.async_list_bs_accounts()
        except GrandstreamApiError as err:
            raise UpdateFailed(str(err)) from err

        return {
            COORDINATOR_KEY_ONLINE: True,
            COORDINATOR_KEY_STATUS: status,
            COORDINATOR_KEY_LINE_STATUS: line_status,
            COORDINATOR_KEY_PHONE_STATUS: phone_status,
            COORDINATOR_KEY_ACCOUNTS: accounts,
        }


def _parse_status_keys(raw: str) -> list[str]:
    """Parse colon or comma separated key list."""
    keys: list[str] = []
    for chunk in raw.replace(",", ":").split(":"):
        key = chunk.strip()
        if key and key not in keys:
            keys.append(key)
    return keys
