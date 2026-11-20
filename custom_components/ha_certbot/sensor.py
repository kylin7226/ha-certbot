"""Certificate status sensor."""
from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    ACME_SERVER_LABELS,
    CONF_ACME_SERVER,
    DOMAIN,
    STATUS_ERROR,
    STATUS_EXPIRED,
    STATUS_NOT_FOUND,
    STATUS_RENEWAL_REQUIRED,
    STATUS_VALID,
)
from .coordinator import HaCertbotCoordinator

ICONS = {
    STATUS_VALID: "mdi:check-circle",
    STATUS_RENEWAL_REQUIRED: "mdi:clock-alert-outline",
    STATUS_EXPIRED: "mdi:alert-circle",
    STATUS_ERROR: "mdi:alert-circle",
    STATUS_NOT_FOUND: "mdi:file-question",
}

ATTRIBUTES = (
    "domain",
    "domains",
    "expiry_date",
    "days_remaining",
    "issuer",
    "serial_number",
    "certificate_path",
    "key_path",
    "auto_renew",
    "last_issued",
    "last_error",
    "error",
)


async def async_setup_entry(hass, entry, async_add_entities) -> None:
    """Add the certificate sensor of one config entry."""
    async_add_entities([HaCertbotCertificateSensor(hass.data[DOMAIN][entry.entry_id])])


class HaCertbotCertificateSensor(CoordinatorEntity[HaCertbotCoordinator], SensorEntity):
    """Reports whether the managed certificate is still valid."""

    _attr_has_entity_name = True
    _attr_translation_key = "certificate"

    def __init__(self, coordinator: HaCertbotCoordinator) -> None:
        """Bind the sensor to the entry's coordinator."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.entry.entry_id}_certificate"
        server = coordinator.entry.data.get(CONF_ACME_SERVER, "")
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.entry.entry_id)},
            name=coordinator.entry.title,
            manufacturer="ha-certbot",
            model=ACME_SERVER_LABELS.get(server, server),
            entry_type=DeviceEntryType.SERVICE,
        )

    @property
    def native_value(self) -> str:
        """Current certificate status."""
        return (self.coordinator.data or {}).get("status", STATUS_NOT_FOUND)

    @property
    def icon(self) -> str:
        """Icon matching the certificate status."""
        return ICONS.get(self.native_value, "mdi:certificate-outline")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Certificate details, including the days left before expiry."""
        data = self.coordinator.data or {}
        return {name: data[name] for name in ATTRIBUTES if data.get(name) is not None}
