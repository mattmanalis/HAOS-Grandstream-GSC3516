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

FALLBACK_STATUS_KEYS: tuple[str, ...] = (
    # Model / firmware / identity keys observed on GSC3516.
    "Pphone_model",
    "P68",
    "P67",
    "Pvendor_fullname",
    # SIP registration keys available via api.values.get.
    "PAccountRegistered1",
    "PAccountRegistered2",
    "PAccountRegistered3",
    "AccountRegistered1",
    "AccountRegistered2",
    "AccountRegistered3",
)


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
        for fallback_key in FALLBACK_STATUS_KEYS:
            if fallback_key not in keys:
                keys.append(fallback_key)

        status: dict[str, str] = {}
        line_status: list[dict[str, object]] = []
        phone_status: str | None = None
        accounts: list[dict[str, object]] = []
        had_success = False

        # Firmware differs: some status endpoints are readable without authenticated session.
        try:
            status = await self.api.async_get_values(keys)
            self._apply_status_fallbacks(status)
            had_success = True
        except GrandstreamApiError:
            status = {}

        try:
            line_status = await self.api.async_get_line_status()
            had_success = True
        except GrandstreamApiError:
            line_status = []

        try:
            phone_status = await self.api.async_get_phone_status()
            had_success = True
        except GrandstreamApiError:
            phone_status = None

        try:
            accounts = await self.api.async_list_bs_accounts()
            had_success = True
        except GrandstreamApiError:
            accounts = []
        if not accounts:
            accounts = self._accounts_from_status(status)

        if not had_success:
            raise UpdateFailed("Unable to poll any supported status endpoint")

        # Keep core host visibility even when p-value polling is auth-limited.
        if "ip" not in status or not str(status.get("ip", "")).strip():
            status["ip"] = self.config_entry.data.get(CONF_HOST, "")

        return {
            COORDINATOR_KEY_ONLINE: True,
            COORDINATOR_KEY_STATUS: status,
            COORDINATOR_KEY_LINE_STATUS: line_status,
            COORDINATOR_KEY_PHONE_STATUS: phone_status,
            COORDINATOR_KEY_ACCOUNTS: accounts,
        }

    @staticmethod
    def _apply_status_fallbacks(status: dict[str, str]) -> None:
        """Normalize firmware/model/SIP keys from p-value variants."""
        if not status.get("product_model"):
            fallback_model = status.get("phone_model") or status.get("Pphone_model")
            if fallback_model:
                status["product_model"] = str(fallback_model)

        if not status.get("prog_version"):
            fallback_fw = status.get("P68")
            if fallback_fw:
                status["prog_version"] = str(fallback_fw)

        if not status.get("mac"):
            fallback_mac = status.get("P67")
            if fallback_mac:
                status["mac"] = str(fallback_mac)

        if not status.get("vendor_fullname"):
            fallback_vendor = status.get("Pvendor_fullname")
            if fallback_vendor:
                status["vendor_fullname"] = str(fallback_vendor)

        # Optional convenience key for SIP registration if no custom key is configured.
        if "sip_registered" not in status:
            for key in (
                "PAccountRegistered1",
                "AccountRegistered1",
                "PAccountRegistered2",
                "AccountRegistered2",
            ):
                value = status.get(key)
                if value is not None and str(value).strip() != "":
                    status["sip_registered"] = str(value)
                    break

    @staticmethod
    def _accounts_from_status(status: dict[str, str]) -> list[dict[str, object]]:
        """Synthesize account registration list when call account API is unauthorized."""
        if not status:
            return []
        accounts: list[dict[str, object]] = []
        for idx in range(1, 4):
            for key in (f"PAccountRegistered{idx}", f"AccountRegistered{idx}"):
                value = status.get(key)
                if value is None or str(value).strip() == "":
                    continue
                accounts.append({"index": idx, "sipReg": str(value)})
                break
        return accounts


def _parse_status_keys(raw: str) -> list[str]:
    """Parse colon or comma separated key list."""
    keys: list[str] = []
    for chunk in raw.replace(",", ":").split(":"):
        key = chunk.strip()
        if key and key not in keys:
            keys.append(key)
    return keys
