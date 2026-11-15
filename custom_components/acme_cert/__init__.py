"""The ACME certificate integration."""
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
    DEFAULT_KEYLENGTH,
    DOMAIN,
    SERVICE_ISSUE,
)
from .coordinator import AcmeCertCoordinator, entry_config
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
        server=server,
        server_url=server_url,
        email=str(config.get(CONF_EMAIL, "")),
        keylength=config.get(CONF_KEYLENGTH, DEFAULT_KEYLENGTH),
        eab_kid=str(config.get(CONF_EAB_KID, "")),
        eab_hmac_key=str(config.get(CONF_EAB_HMAC_KEY, "")),
    )

    coordinator = AcmeCertCoordinator(hass, entry, manager, domains)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await coordinator.async_config_entry_first_refresh()
    await hass.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    _register_services(hass)

    _LOGGER.info(
        "Managing %s through %s, certificates are published in %s",
        ", ".join(domains),
        config[CONF_DNS_PROVIDER],
        ssl_dir,
    )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    coordinator: AcmeCertCoordinator = hass.data[DOMAIN][entry.entry_id]
    coordinator.apply_options()
    await coordinator.async_request_refresh()


def _register_services(hass: HomeAssistant) -> None:
    """Register the integration services once."""
    if hass.services.has_service(DOMAIN, SERVICE_ISSUE):
        return

    async def async_issue_certificate(call: ServiceCall) -> None:
        entry_id: str = call.data[ATTR_CONFIG_ENTRY_ID]
        coordinator: AcmeCertCoordinator | None = hass.data.get(DOMAIN, {}).get(entry_id)
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
