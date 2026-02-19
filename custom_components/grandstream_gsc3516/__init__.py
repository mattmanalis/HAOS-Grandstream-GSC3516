"""Grandstream GSC3516 integration."""

from __future__ import annotations

from copy import deepcopy
import logging

from aiohttp import web
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.components.http import HomeAssistantView
from homeassistant.exceptions import ConfigEntryNotReady, ServiceValidationError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.service import async_register_admin_service

from .api import GrandstreamApiClient, GrandstreamApiError
from .const import (
    ATTR_ENTRY_ID,
    ATTR_NUMBER,
    CONF_CALL_API_ACCOUNT,
    CONF_CALL_API_DIALPLAN,
    CONF_CALL_API_HS,
    CONF_CALL_API_PASSCODE,
    CONF_CALL_API_USE_PASSCODE,
    CONF_WEBHOOK_ID,
    CONF_WEBHOOK_PUSH_ENABLED,
    CONF_DIAL_NUMBER_PVALUE,
    CONF_DIAL_TRIGGER_PVALUE,
    CONF_DIAL_TRIGGER_VALUE,
    CONF_HANGUP_PVALUE,
    CONF_HANGUP_VALUE,
    CONF_API_SID,
    CONF_USE_CALL_API,
    COORDINATOR_KEY_LINE_STATUS,
    COORDINATOR_KEY_ONLINE,
    COORDINATOR_KEY_PHONE_STATUS,
    DEFAULT_CALL_API_ACCOUNT,
    DEFAULT_CALL_API_DIALPLAN,
    DEFAULT_CALL_API_HS,
    DEFAULT_CALL_API_USE_PASSCODE,
    DEFAULT_WEBHOOK_PUSH_ENABLED,
    DEFAULT_USE_CALL_API,
    CONF_USE_HTTPS,
    CONF_VERIFY_SSL,
    DOMAIN,
    PLATFORMS,
    SERVICE_DIAL,
    SERVICE_HANGUP,
)
from .coordinator import GrandstreamDataUpdateCoordinator


GrandstreamConfigEntry = ConfigEntry[GrandstreamDataUpdateCoordinator]
_LOGGER = logging.getLogger(__name__)
WEBHOOK_VIEW_KEY = "webhook_view_registered"
WEBHOOK_MAP_KEY = "webhook_map"


class GrandstreamWebhookView(HomeAssistantView):
    """Receive push events from Grandstream outbound notifications."""

    url = "/api/grandstream_gsc3516/{webhook_id}"
    name = "api:grandstream_gsc3516:webhook"
    requires_auth = False

    async def get(self, request: web.Request) -> web.Response:
        return await self._handle(request)

    async def post(self, request: web.Request) -> web.Response:
        return await self._handle(request)

    async def _handle(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        domain_data = hass.data.setdefault(DOMAIN, {})
        webhook_map: dict[str, str] = domain_data.setdefault(WEBHOOK_MAP_KEY, {})
        webhook_id = str(request.match_info.get("webhook_id", "")).strip()
        entry_id = webhook_map.get(webhook_id)
        if not entry_id:
            return web.json_response({"status": "error", "message": "unknown webhook"}, status=404)

        coordinator = _get_coordinator(hass, entry_id)
        event_raw = str(request.query.get("event", "")).strip().lower()
        if not event_raw and request.can_read_body:
            try:
                data = await request.post()
                event_raw = str(data.get("event", "")).strip().lower()
            except Exception:
                event_raw = ""

        mapped = _map_push_event(event_raw)
        if mapped is None:
            return web.json_response(
                {"status": "ignored", "event": event_raw, "message": "unsupported event"}
            )

        _apply_push_event_to_coordinator(coordinator, mapped)
        return web.json_response({"status": "ok", "event": mapped})


async def async_setup_entry(hass: HomeAssistant, entry: GrandstreamConfigEntry) -> bool:
    """Set up Grandstream GSC3516 from a config entry."""
    session = async_get_clientsession(
        hass,
        verify_ssl=entry.options.get(CONF_VERIFY_SSL, entry.data.get(CONF_VERIFY_SSL, False)),
    )

    api = GrandstreamApiClient(
        host=entry.data[CONF_HOST],
        port=entry.data[CONF_PORT],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        use_https=entry.data.get(CONF_USE_HTTPS, False),
        session=session,
        static_sid=entry.options.get(CONF_API_SID, "").strip() or None,
        call_api_use_passcode=bool(
            entry.options.get(CONF_CALL_API_USE_PASSCODE, DEFAULT_CALL_API_USE_PASSCODE)
            or str(entry.options.get(CONF_CALL_API_PASSCODE, "")).strip()
        ),
        call_api_passcode=str(entry.options.get(CONF_CALL_API_PASSCODE, "")).strip() or None,
        call_api_hs=bool(entry.options.get(CONF_CALL_API_HS, DEFAULT_CALL_API_HS)),
    )

    coordinator = GrandstreamDataUpdateCoordinator(hass, entry, api)
    try:
        await coordinator.async_config_entry_first_refresh()
    except GrandstreamApiError as err:
        raise ConfigEntryNotReady(f"Unable to connect to Grandstream device: {err}") from err

    entry.runtime_data = coordinator
    domain_data = hass.data.setdefault(DOMAIN, {})
    coordinators = domain_data.setdefault("coordinators", {})
    coordinators[entry.entry_id] = coordinator
    await _async_register_webhook_view(hass)
    _register_entry_webhook(hass, entry)
    await _async_register_services(hass)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: GrandstreamConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        coordinators = hass.data.setdefault(DOMAIN, {}).setdefault("coordinators", {})
        coordinators.pop(entry.entry_id, None)
        _unregister_entry_webhook(hass, entry.entry_id)
    return unload_ok


def get_device_info(entry: GrandstreamConfigEntry, status: dict[str, str]) -> DeviceInfo:
    """Build Home Assistant device metadata."""
    model = status.get("product_model") or "GSC3516"
    manufacturer = status.get("vendor_fullname") or "Grandstream"
    sw_version = status.get("prog_version")
    mac = status.get("mac") or entry.entry_id

    return DeviceInfo(
        identifiers={(DOMAIN, mac)},
        name=f"Grandstream {entry.title}",
        manufacturer=manufacturer,
        model=model,
        sw_version=sw_version,
        configuration_url=f"{'https' if entry.data.get(CONF_USE_HTTPS, False) else 'http'}://{entry.data[CONF_HOST]}",
    )


async def _async_register_services(hass: HomeAssistant) -> None:
    """Register integration services once."""
    if hass.services.has_service(DOMAIN, SERVICE_DIAL):
        return

    async def _handle_dial(call) -> None:
        entry_id = call.data[ATTR_ENTRY_ID]
        number = call.data[ATTR_NUMBER]
        coordinator = _get_coordinator(hass, entry_id)
        options = coordinator.config_entry.options

        if bool(options.get(CONF_USE_CALL_API, DEFAULT_USE_CALL_API)):
            account = int(options.get(CONF_CALL_API_ACCOUNT, DEFAULT_CALL_API_ACCOUNT))
            dialplan = str(options.get(CONF_CALL_API_DIALPLAN, DEFAULT_CALL_API_DIALPLAN)).strip()
            await coordinator.api.async_make_call(account=account, number=number, dialplan=dialplan)
            await coordinator.async_request_refresh()
            return

        payload: dict[str, str] = {}
        number_key = str(options.get(CONF_DIAL_NUMBER_PVALUE, "")).strip()
        trigger_key = str(options.get(CONF_DIAL_TRIGGER_PVALUE, "")).strip()
        trigger_value = str(options.get(CONF_DIAL_TRIGGER_VALUE, "1"))
        if number_key:
            payload[number_key] = number
        if trigger_key:
            payload[trigger_key] = trigger_value
        if not payload:
            raise ServiceValidationError(
                "No dial mapping configured. Set dial_number_pvalue and/or dial_trigger_pvalue in options."
            )

        await coordinator.api.async_set_values(payload)
        await coordinator.async_request_refresh()

    async def _handle_hangup(call) -> None:
        entry_id = call.data[ATTR_ENTRY_ID]
        coordinator = _get_coordinator(hass, entry_id)
        options = coordinator.config_entry.options

        if bool(options.get(CONF_USE_CALL_API, DEFAULT_USE_CALL_API)):
            line = _find_active_line(coordinator)
            if line is None:
                raise ServiceValidationError(
                    "No active line to hang up. Current line state is idle/none."
                )
            await coordinator.api.async_phone_operation(cmd="endcall", arg=str(line))
            await coordinator.async_request_refresh()
            return

        hangup_key = str(options.get(CONF_HANGUP_PVALUE, "")).strip()
        if not hangup_key:
            raise ServiceValidationError(
                "No hangup mapping configured. Set hangup_pvalue in options."
            )
        hangup_value = str(options.get(CONF_HANGUP_VALUE, "1"))

        await coordinator.api.async_set_values({hangup_key: hangup_value})
        await coordinator.async_request_refresh()

    async_register_admin_service(
        hass,
        DOMAIN,
        SERVICE_DIAL,
        _handle_dial,
        schema=vol.Schema(
            {
                vol.Required(ATTR_ENTRY_ID): cv.string,
                vol.Required(ATTR_NUMBER): cv.string,
            }
        ),
    )
    async_register_admin_service(
        hass,
        DOMAIN,
        SERVICE_HANGUP,
        _handle_hangup,
        schema=vol.Schema({vol.Required(ATTR_ENTRY_ID): cv.string}),
    )


def _get_coordinator(hass: HomeAssistant, entry_id: str) -> GrandstreamDataUpdateCoordinator:
    coordinators = hass.data.setdefault(DOMAIN, {}).setdefault("coordinators", {})
    coordinator = coordinators.get(entry_id)
    if coordinator is None:
        raise ServiceValidationError(f"Entry not found: {entry_id}")
    return coordinator


def _find_active_line(coordinator: GrandstreamDataUpdateCoordinator) -> int | None:
    lines = coordinator.data.get(COORDINATOR_KEY_LINE_STATUS, [])
    if not isinstance(lines, list):
        return None
    for line in lines:
        if not isinstance(line, dict):
            continue
        state = str(line.get("state", "")).strip().lower()
        if state and state not in {"none", "available", "idle"}:
            try:
                return int(line.get("line"))
            except (TypeError, ValueError):
                continue
    return None


async def _async_register_webhook_view(hass: HomeAssistant) -> None:
    """Register webhook HTTP view once."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    if domain_data.get(WEBHOOK_VIEW_KEY):
        return
    hass.http.register_view(GrandstreamWebhookView())
    domain_data[WEBHOOK_VIEW_KEY] = True


def _entry_webhook_id(entry: ConfigEntry) -> str:
    configured = str(entry.options.get(CONF_WEBHOOK_ID, "")).strip()
    if configured:
        return configured
    return f"gsc3516_{entry.data[CONF_HOST].replace('.', '_')}"


def _register_entry_webhook(hass: HomeAssistant, entry: ConfigEntry) -> None:
    domain_data = hass.data.setdefault(DOMAIN, {})
    webhook_map: dict[str, str] = domain_data.setdefault(WEBHOOK_MAP_KEY, {})
    if not bool(entry.options.get(CONF_WEBHOOK_PUSH_ENABLED, DEFAULT_WEBHOOK_PUSH_ENABLED)):
        return
    webhook_id = _entry_webhook_id(entry)
    webhook_map[webhook_id] = entry.entry_id
    _LOGGER.debug(
        "Grandstream webhook registered for entry %s: /api/grandstream_gsc3516/%s",
        entry.entry_id,
        webhook_id,
    )


def _unregister_entry_webhook(hass: HomeAssistant, entry_id: str) -> None:
    domain_data = hass.data.setdefault(DOMAIN, {})
    webhook_map: dict[str, str] = domain_data.setdefault(WEBHOOK_MAP_KEY, {})
    stale = [hook for hook, mapped in webhook_map.items() if mapped == entry_id]
    for hook in stale:
        webhook_map.pop(hook, None)


def _map_push_event(event_raw: str) -> str | None:
    mapping = {
        "incoming": "ringing",
        "outgoing": "dialing",
        "connected": "connected",
        "established": "connected",
        "terminated": "none",
        "idle": "none",
    }
    if event_raw in mapping:
        return mapping[event_raw]
    if event_raw in {"ringing", "dialing", "connected", "none", "available"}:
        return event_raw
    return None


def _apply_push_event_to_coordinator(
    coordinator: GrandstreamDataUpdateCoordinator,
    line_state: str,
) -> None:
    data = deepcopy(coordinator.data) if coordinator.data else {}
    if not isinstance(data, dict):
        data = {}
    data[COORDINATOR_KEY_ONLINE] = True
    if line_state in {"none", "available"}:
        data[COORDINATOR_KEY_PHONE_STATUS] = "available"
        data[COORDINATOR_KEY_LINE_STATUS] = [{"line": 1, "state": "none"}]
    elif line_state == "ringing":
        data[COORDINATOR_KEY_PHONE_STATUS] = "ringing"
        data[COORDINATOR_KEY_LINE_STATUS] = [{"line": 1, "state": "ringing"}]
    elif line_state == "dialing":
        data[COORDINATOR_KEY_PHONE_STATUS] = "dialing"
        data[COORDINATOR_KEY_LINE_STATUS] = [{"line": 1, "state": "dialing"}]
    elif line_state == "connected":
        data[COORDINATOR_KEY_PHONE_STATUS] = "connected"
        data[COORDINATOR_KEY_LINE_STATUS] = [{"line": 1, "state": "connected"}]
    coordinator.async_set_updated_data(data)
