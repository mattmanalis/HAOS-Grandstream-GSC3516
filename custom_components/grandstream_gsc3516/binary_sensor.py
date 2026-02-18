"""Binary sensors for Grandstream GSC3516."""

from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
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
    COORDINATOR_KEY_LINE_STATUS,
    COORDINATOR_KEY_PHONE_STATUS,
    COORDINATOR_KEY_STATUS,
    DEFAULT_CALL_ACTIVE_VALUES,
    DEFAULT_CALL_RINGING_VALUES,
    DEFAULT_SIP_REGISTERED_ON_VALUES,
)
from .coordinator import GrandstreamDataUpdateCoordinator


@dataclass(frozen=True, kw_only=True)
class GrandstreamBinarySensorDescription:
    """Description for Grandstream binary sensors."""

    key: str
    name: str
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
            if not key:
                return None
            raw = str(self._status.get(key, "")).strip().lower()
            on_values = _parse_values(
                self._entry.options.get(
                    CONF_SIP_REGISTERED_ON_VALUES, DEFAULT_SIP_REGISTERED_ON_VALUES
                )
            )
            return raw in on_values

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
        if self.entity_description.key == "sip_registered":
            return bool(str(self._entry.options.get(CONF_SIP_REGISTERED_KEY, "")).strip())
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
            return str(phone_state).strip().lower()
        return None


def _parse_values(raw: str) -> set[str]:
    return {chunk.strip().lower() for chunk in raw.split(",") if chunk.strip()}
