"""Sensor platform for Grandstream GSC3516."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import get_device_info
from .const import CONF_CALL_STATUS_KEY, COORDINATOR_KEY_LINE_STATUS, COORDINATOR_KEY_PHONE_STATUS, COORDINATOR_KEY_STATUS
from .coordinator import GrandstreamDataUpdateCoordinator


@dataclass(frozen=True, kw_only=True)
class GrandstreamSensorDescription(SensorEntityDescription):
    """Describes Grandstream status sensor."""

    status_key: str


SENSORS: tuple[GrandstreamSensorDescription, ...] = (
    GrandstreamSensorDescription(
        key="product_model",
        translation_key="product_model",
        name="Model",
        status_key="product_model",
    ),
    GrandstreamSensorDescription(
        key="prog_version",
        translation_key="firmware",
        name="Firmware",
        status_key="prog_version",
    ),
    GrandstreamSensorDescription(
        key="sys_uptime",
        translation_key="uptime",
        name="Uptime",
        status_key="sys_uptime",
    ),
    GrandstreamSensorDescription(
        key="ip",
        translation_key="ip_address",
        name="IP Address",
        status_key="ip",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Grandstream sensors."""
    coordinator: GrandstreamDataUpdateCoordinator = entry.runtime_data

    entities = [GrandstreamStatusSensor(entry, coordinator, description) for description in SENSORS]
    entities.append(GrandstreamCallStateSensor(entry, coordinator))
    async_add_entities(entities)


class GrandstreamStatusSensor(CoordinatorEntity[GrandstreamDataUpdateCoordinator], SensorEntity):
    """Represents a status field from the speaker."""

    _attr_has_entity_name = True

    def __init__(
        self,
        entry: ConfigEntry,
        coordinator: GrandstreamDataUpdateCoordinator,
        description: GrandstreamSensorDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"

    @property
    def native_value(self) -> str | None:
        """Return the value of the status field."""
        raw = self._status.get(self.entity_description.status_key)
        if raw is None and self.entity_description.status_key == "ip":
            raw = self._entry.data.get(CONF_HOST)
        if raw is None:
            return None
        return str(raw)

    @property
    def available(self) -> bool:
        """Entity is available if key exists in payload."""
        if self.entity_description.status_key == "ip":
            return True
        return super().available and self.entity_description.status_key in self._status

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose host and raw status key for easier debugging."""
        return {
            "host": self._entry.data[CONF_HOST],
            "status_key": self.entity_description.status_key,
        }

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        return get_device_info(self._entry, self._status)

    @property
    def _status(self) -> dict[str, str]:
        data = self.coordinator.data.get(COORDINATOR_KEY_STATUS, {})
        if isinstance(data, dict):
            return data
        return {}


class GrandstreamCallStateSensor(CoordinatorEntity[GrandstreamDataUpdateCoordinator], SensorEntity):
    """Represents the configured call state key value."""

    _attr_has_entity_name = True
    _attr_name = "Call State"

    def __init__(self, entry: ConfigEntry, coordinator: GrandstreamDataUpdateCoordinator) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_call_state"

    @property
    def native_value(self) -> str | None:
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

        key = self._call_state_key
        if key:
            value = self._status.get(key)
            if value is not None:
                state = str(value).strip().lower()
                if state in {"unauthorized", "forbidden", "invalid request"}:
                    return None
                return state

        phone_status = self.coordinator.data.get(COORDINATOR_KEY_PHONE_STATUS)
        if phone_status is not None:
            state = str(phone_status).strip().lower()
            if state in {"unauthorized", "forbidden", "invalid request"}:
                return None
            return state
        return None

    @property
    def available(self) -> bool:
        return True

    @property
    def device_info(self) -> DeviceInfo:
        return get_device_info(self._entry, self._status)

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        return {"status_key": self._call_state_key}

    @property
    def _call_state_key(self) -> str:
        return str(self._entry.options.get(CONF_CALL_STATUS_KEY, "")).strip()

    @property
    def _status(self) -> dict[str, str]:
        data = self.coordinator.data.get(COORDINATOR_KEY_STATUS, {})
        if isinstance(data, dict):
            return data
        return {}
