"""Binary sensors for Grandstream GSC3516."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.core import HomeAssistant

from . import get_device_info
from .const import (
    CONF_CALL_ACTIVE_VALUES,
    CONF_CALL_RINGING_VALUES,
    CONF_CALL_STATUS_KEY,
    CONF_SIP_REGISTERED_KEY,
    CONF_SIP_REGISTERED_ON_VALUES,
    COORDINATOR_KEY_ACCOUNTS,
    COORDINATOR_KEY_LINE_STATUS,
    COORDINATOR_KEY_PHONE_STATUS,
    COORDINATOR_KEY_STATUS,
    DEFAULT_CALL_ACTIVE_VALUES,
    DEFAULT_CALL_RINGING_VALUES,
    DEFAULT_SIP_REGISTERED_ON_VALUES,
)
from .coordinator import GrandstreamDataUpdateCoordinator


@dataclass(frozen=True, kw_only=True)
class GrandstreamBinarySensorDescription(BinarySensorEntityDescription):
    """Description for Grandstream binary sensors."""

    # Explicitly define to support HA builds that strictly access this attr.
    entity_registry_enabled_default: bool = True
    device_class: BinarySensorDeviceClass | None = None


DESCRIPTIONS = (
    GrandstreamBinarySensorDescription(
        key="online",
        name="Online",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
    ),
    GrandstreamBinarySensorDescription(
        key="sip_registered",
        name="SIP Registered",
    ),
    GrandstreamBinarySensorDescription(
        key="in_call",
        name="In Call",
    ),
    GrandstreamBinarySensorDescription(
        key="ringing",
        name="Ringing",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Grandstream binary sensors."""
    coordinator: GrandstreamDataUpdateCoordinator = entry.runtime_data
    async_add_entities(GrandstreamBinarySensor(entry, coordinator, desc) for desc in DESCRIPTIONS)


class GrandstreamBinarySensor(
    CoordinatorEntity[GrandstreamDataUpdateCoordinator], BinarySensorEntity
):
    """Represents Grandstream binary state."""

    _attr_has_entity_name = True

    def __init__(
        self,
        entry: ConfigEntry,
        coordinator: GrandstreamDataUpdateCoordinator,
        description: GrandstreamBinarySensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_name = description.name
        self._attr_device_class = description.device_class

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return get_device_info(self._entry, self._status)

    @property
    def is_on(self) -> bool | None:
        """Return current binary state."""
        if self.entity_description.key == "online":
            return self.coordinator.last_update_success
        if not self.coordinator.last_update_success:
            return None

        if self.entity_description.key == "sip_registered":
            key = str(self._entry.options.get(CONF_SIP_REGISTERED_KEY, "")).strip()
            on_values = _parse_values(
                self._entry.options.get(
                    CONF_SIP_REGISTERED_ON_VALUES, DEFAULT_SIP_REGISTERED_ON_VALUES
                )
            )
            if key:
                raw = str(self._status.get(key, "")).strip().lower()
                if raw:
                    return raw in on_values
            else:
                fallback = self._sip_registered_from_status(on_values)
                if fallback is not None:
                    return fallback
            return self._sip_registered_from_accounts

        call_key = str(self._entry.options.get(CONF_CALL_STATUS_KEY, "")).strip()
        raw_state = self._call_state

        if self.entity_description.key == "in_call":
            if raw_state is None:
                return None
            on_values = _parse_values(
                self._entry.options.get(CONF_CALL_ACTIVE_VALUES, DEFAULT_CALL_ACTIVE_VALUES)
            )
            return raw_state in on_values

        if self.entity_description.key == "ringing":
            if raw_state is None:
                return None
            on_values = _parse_values(
                self._entry.options.get(CONF_CALL_RINGING_VALUES, DEFAULT_CALL_RINGING_VALUES)
            )
            return raw_state in on_values

        return None

    @property
    def available(self) -> bool:
        """Return availability for each sensor."""
        if self.entity_description.key == "online":
            return True
        return True

    @property
    def _status(self) -> dict[str, str]:
        data = self.coordinator.data.get(COORDINATOR_KEY_STATUS, {})
        if isinstance(data, dict):
            return data
        return {}

    @property
    def _call_state(self) -> str | None:
        line_states = self.coordinator.data.get(COORDINATOR_KEY_LINE_STATUS, [])
        if isinstance(line_states, list):
            for line in line_states:
                if not isinstance(line, dict):
                    continue
                state = str(line.get("state", "")).strip().lower()
                if state and state != "none":
                    return state
            if line_states:
                return "idle"

        call_key = str(self._entry.options.get(CONF_CALL_STATUS_KEY, "")).strip()
        if call_key:
            return str(self._status.get(call_key, "")).strip().lower()

        phone_state = self.coordinator.data.get(COORDINATOR_KEY_PHONE_STATUS)
        if phone_state is not None:
            raw = str(phone_state).strip().lower()
            if raw in {"unauthorized", "forbidden", "invalid request"}:
                return None
            return raw
        return None

    @property
    def _sip_registered_from_accounts(self) -> bool | None:
        accounts = self.coordinator.data.get(COORDINATOR_KEY_ACCOUNTS, [])
        if not isinstance(accounts, list) or not accounts:
            return None

        true_tokens = {"1", "true", "yes", "ok", "registered", "online", "available"}
        false_tokens = {"0", "false", "no", "offline", "unregistered", "unknown"}
        saw_false = False

        for account in accounts:
            if not isinstance(account, dict):
                continue
            for key in ("sipReg", "register_status", "registered", "status"):
                if key not in account:
                    continue
                value = str(account.get(key, "")).strip().lower()
                if value in true_tokens:
                    return True
                if value in false_tokens:
                    saw_false = True

        if saw_false:
            return False
        return None

    def _sip_registered_from_status(self, on_values: set[str]) -> bool | None:
        """Infer SIP registration from common p-value keys."""
        keys = (
            "sip_registered",
            "PAccountRegistered1",
            "AccountRegistered1",
            "PAccountRegistered2",
            "AccountRegistered2",
        )
        for key in keys:
            raw_value = self._status.get(key)
            if raw_value is None:
                continue
            raw = str(raw_value).strip().lower()
            if not raw:
                continue
            if raw in on_values:
                return True
            if raw in {"0", "false", "no", "offline", "unregistered", "unknown"}:
                return False
        return None


def _parse_values(raw: str) -> set[str]:
    return {chunk.strip().lower() for chunk in raw.split(",") if chunk.strip()}
