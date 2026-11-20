"""The ha-certbot integration."""
from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryError, ServiceValidationError
from homeassistant.helpers import config_validation as cv

from .acme import (
    AcmeError,
    CertificateManager,
    entry_unique_id,
    parse_domains,
    resolve_data_dir,
    resolve_ssl_dir,
)
from .const import (
    ACME_SERVERS,
    ATTR_CONFIG_ENTRY_ID,
    ATTR_FORCE,
    CONF_ACME_SERVER,
    CONF_ACME_SERVER_URL,
    CONF_DNS_PROVIDER,
    CONF_DOMAINS,
    CONF_EAB_HMAC_KEY,
    CONF_EAB_KID,
    CONF_EMAIL,
    CONF_KEYLENGTH,
    CONF_LEGACY_ENTRY_ID,
    DEFAULT_KEYLENGTH,
    DOMAIN,
    SERVICE_ISSUE,
)
from .coordinator import HaCertbotCoordinator, entry_config
from .dns import DnsError

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.SENSOR]

ISSUE_SERVICE_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Optional(ATTR_FORCE, default=False): cv.boolean,
    }
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up one certificate from a config entry."""
    config = entry_config(entry)
    server = config[CONF_ACME_SERVER]
    server_url = config.get(CONF_ACME_SERVER_URL) or ACME_SERVERS[server]

    try:
        domains = await hass.async_add_executor_job(parse_domains, config[CONF_DOMAINS])
    except ValueError as err:
        raise ConfigEntryError(str(err)) from err

    data_dir = resolve_data_dir(hass)
    ssl_dir = resolve_ssl_dir(hass)
    manager = CertificateManager(
        data_dir=data_dir,
        ssl_dir=ssl_dir,
        entry_id=entry.entry_id,
        server=server,
        server_url=server_url,
        email=str(config.get(CONF_EMAIL, "")),
        keylength=config.get(CONF_KEYLENGTH, DEFAULT_KEYLENGTH),
        eab_kid=str(config.get(CONF_EAB_KID, "")),
        eab_hmac_key=str(config.get(CONF_EAB_HMAC_KEY, "")),
    )

    if legacy_entry_id := config.get(CONF_LEGACY_ENTRY_ID):
        from .migration import import_legacy

        legacy_entry = hass.config_entries.async_get_entry(legacy_entry_id)
        if legacy_entry is not None and not legacy_entry.disabled_by:
            raise ConfigEntryError("Disable the legacy entry before importing it")
        try:
            await hass.async_add_executor_job(import_legacy, manager, legacy_entry_id, domains)
        except (OSError, ValueError, TypeError, AcmeError) as err:
            raise ConfigEntryError(f"Legacy import failed ({type(err).__name__}); original files are unchanged") from None
        hass.config_entries.async_update_entry(entry, data={
            key: value for key, value in entry.data.items() if key != CONF_LEGACY_ENTRY_ID
        })

    coordinator = HaCertbotCoordinator(hass, entry, manager, domains)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    try:
        await coordinator.async_config_entry_first_refresh()
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except BaseException:
        await coordinator.async_shutdown()
        hass.data[DOMAIN].pop(entry.entry_id, None)
        raise
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    _register_services(hass)
    coordinator.start()

    _LOGGER.info(
        "Managing %s through %s, certificates are published in %s",
        ", ".join(domains),
        config[CONF_DNS_PROVIDER],
        ssl_dir,
    )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        coordinator = hass.data[DOMAIN][entry.entry_id]
        await coordinator.async_shutdown()
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    if entry.version > 2:
        return False
    if entry.version == 1:
        config = entry_config(entry)
        domains = parse_domains(config[CONF_DOMAINS])
        server_url = config.get(CONF_ACME_SERVER_URL) or ACME_SERVERS[config[CONF_ACME_SERVER]]
        unique_id = entry_unique_id(server_url, domains[0])
        existing = hass.config_entries.async_entry_for_domain_unique_id(DOMAIN, unique_id)
        if existing is not None and existing.entry_id != entry.entry_id:
            _LOGGER.error("Cannot migrate a duplicate certificate entry")
            return False
        hass.config_entries.async_update_entry(entry, unique_id=unique_id, version=2)
    return True


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    hass.config_entries.async_schedule_reload(entry.entry_id)


def _register_services(hass: HomeAssistant) -> None:
    """Register the integration services once."""
    if hass.services.has_service(DOMAIN, SERVICE_ISSUE):
        return

    async def async_issue_certificate(call: ServiceCall) -> None:
        entry_id: str = call.data[ATTR_CONFIG_ENTRY_ID]
        coordinator: HaCertbotCoordinator | None = hass.data.get(DOMAIN, {}).get(entry_id)
        if coordinator is None:
            raise ServiceValidationError(
                f"ACME certificate entry {entry_id} is not loaded"
            )
        try:
            await coordinator.async_issue(force=bool(call.data.get(ATTR_FORCE, False)))
        except (AcmeError, DnsError) as err:
            raise ServiceValidationError(str(err)) from err

    hass.services.async_register(
        DOMAIN, SERVICE_ISSUE, async_issue_certificate, schema=ISSUE_SERVICE_SCHEMA
    )
