"""Media player platform for Grandstream GSC3516."""

from __future__ import annotations

from typing import Any

from homeassistant.components.media_player import MediaPlayerEntity
from homeassistant.components.media_player.const import MediaPlayerEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import get_device_info
from .const import (
    CONF_MUTE_FALSE_VALUE,
    CONF_MUTE_PVALUE,
    CONF_MUTE_TRUE_VALUE,
    CONF_VOLUME_PVALUE,
    COORDINATOR_KEY_STATUS,
    DEFAULT_MUTE_FALSE_VALUE,
    DEFAULT_MUTE_TRUE_VALUE,
)
from .coordinator import GrandstreamDataUpdateCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up media player for a config entry."""
    coordinator: GrandstreamDataUpdateCoordinator = entry.runtime_data
    async_add_entities([GrandstreamSpeakerEntity(entry, coordinator)])


class GrandstreamSpeakerEntity(CoordinatorEntity[GrandstreamDataUpdateCoordinator], MediaPlayerEntity):
    """Representation of a Grandstream GSC3516 speaker."""

    _attr_has_entity_name = True
    _attr_name = "Speaker"

    def __init__(self, entry: ConfigEntry, coordinator: GrandstreamDataUpdateCoordinator) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_speaker"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info."""
        status = self.coordinator.data.get(COORDINATOR_KEY_STATUS, {})
        return get_device_info(self._entry, status)

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return super().available and bool(self.coordinator.data.get("online", False))

    @property
    def supported_features(self) -> MediaPlayerEntityFeature:
        """Return dynamic feature set based on configured P-values."""
        features = MediaPlayerEntityFeature(0)
        if self._volume_key:
            features |= MediaPlayerEntityFeature.VOLUME_SET
        if self._mute_key:
            features |= MediaPlayerEntityFeature.VOLUME_MUTE
        return features

    @property
    def volume_level(self) -> float | None:
        """Return volume level in range 0.0-1.0."""
        if not self._volume_key:
            return None

        raw = self._status.get(self._volume_key)
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return None

        if value > 1:
            value = value / 100
        return max(0.0, min(1.0, value))

    @property
    def is_volume_muted(self) -> bool | None:
        """Return muted state."""
        if not self._mute_key:
            return None

        raw = str(self._status.get(self._mute_key, "")).strip().lower()
        mute_true = str(
            self._entry.options.get(CONF_MUTE_TRUE_VALUE, DEFAULT_MUTE_TRUE_VALUE)
        ).strip().lower()
        mute_false = str(
            self._entry.options.get(CONF_MUTE_FALSE_VALUE, DEFAULT_MUTE_FALSE_VALUE)
        ).strip().lower()

        if raw == mute_true:
            return True
        if raw == mute_false:
            return False
        if raw in {"1", "true", "yes", "on"}:
            return True
        if raw in {"0", "false", "no", "off"}:
            return False
        return None

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Return raw polled key-values for troubleshooting."""
        return self._status

    async def async_set_volume_level(self, volume: float) -> None:
        """Set speaker volume."""
        if not self._volume_key:
            return

        target = str(int(max(0.0, min(1.0, volume)) * 100))
        await self.coordinator.api.async_set_value(self._volume_key, target)
        await self.coordinator.async_request_refresh()

    async def async_mute_volume(self, mute: bool) -> None:
        """Mute/unmute speaker."""
        if not self._mute_key:
            return

        value = (
            str(self._entry.options.get(CONF_MUTE_TRUE_VALUE, DEFAULT_MUTE_TRUE_VALUE))
            if mute
            else str(self._entry.options.get(CONF_MUTE_FALSE_VALUE, DEFAULT_MUTE_FALSE_VALUE))
        )
        await self.coordinator.api.async_set_value(self._mute_key, value)
        await self.coordinator.async_request_refresh()

    @property
    def _volume_key(self) -> str:
        return str(self._entry.options.get(CONF_VOLUME_PVALUE, "")).strip()

    @property
    def _mute_key(self) -> str:
        return str(self._entry.options.get(CONF_MUTE_PVALUE, "")).strip()

    @property
    def _status(self) -> dict[str, str]:
        data = self.coordinator.data.get(COORDINATOR_KEY_STATUS, {})
        if isinstance(data, dict):
            return data
        return {}
