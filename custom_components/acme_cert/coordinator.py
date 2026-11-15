"""Certificate status polling and renewal scheduling."""
from __future__ import annotations

import asyncio
import datetime
import functools
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .acme import AcmeError, CertificateManager, IssueResult, describe_error
from .const import (
    CONF_AUTO_RENEW,
    CONF_CHECK_HOURS,
    CONF_DAYS,
    CONF_DNS_CREDENTIALS,
    CONF_DNS_PROVIDER,
    CONF_PROPAGATION_INTERVAL,
    CONF_PROPAGATION_TIMEOUT,
    CONF_RELOAD_SERVICE,
    DEFAULT_AUTO_RENEW,
    DEFAULT_CHECK_HOURS,
    DEFAULT_DAYS,
    DEFAULT_PROPAGATION_INTERVAL,
    DEFAULT_PROPAGATION_TIMEOUT,
    DOMAIN,
    EVENT_FAILED,
    EVENT_ISSUED,
    STATUS_EXPIRED,
    STATUS_NOT_FOUND,
    STATUS_RENEWAL_REQUIRED,
)
from .dns import DnsError

_LOGGER = logging.getLogger(__name__)


def entry_config(entry: ConfigEntry) -> dict[str, Any]:
    """Config entry data with the values from the options flow applied on top."""
    return {**entry.data, **entry.options}


class AcmeCertCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Reads the installed certificate and renews it when the threshold is reached."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        manager: CertificateManager,
        domains: list[str],
    ) -> None:
        self.entry = entry
        self.manager = manager
        self.domains = domains
        self.lock = asyncio.Lock()
        self.last_error: str | None = None
        self.last_issued: str | None = None
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}.{entry.entry_id}",
            update_interval=self._interval(entry_config(entry)),
        )

    @staticmethod
    def _interval(config: dict[str, Any]) -> datetime.timedelta:
        hours = int(config.get(CONF_CHECK_HOURS, DEFAULT_CHECK_HOURS))
        return datetime.timedelta(hours=hours)

    def apply_options(self) -> None:
        """Pick up a changed check interval after the options flow."""
        self.update_interval = self._interval(entry_config(self.entry))

    async def _async_update_data(self) -> dict[str, Any]:
        data = await self.hass.async_add_executor_job(self._status)
        if self._renewal_due(data):
            self.hass.async_create_task(self.async_issue())
        return data

    def _status(self) -> dict[str, Any]:
        config = entry_config(self.entry)
        data = self.manager.certificate_status(
            self.domains, int(config.get(CONF_DAYS, DEFAULT_DAYS))
        )
        data["auto_renew"] = bool(config.get(CONF_AUTO_RENEW, DEFAULT_AUTO_RENEW))
        data["last_error"] = self.last_error
        data["last_issued"] = self.last_issued
        return data

    def _renewal_due(self, data: dict[str, Any]) -> bool:
        if not data["auto_renew"] or self.lock.locked():
            return False
        return data["status"] in (STATUS_RENEWAL_REQUIRED, STATUS_EXPIRED, STATUS_NOT_FOUND)

    async def async_issue(self, force: bool = False) -> IssueResult:
        """Issue or renew the certificate now."""
        if self.lock.locked():
            raise AcmeError("another certificate operation is already running")
        async with self.lock:
            self.last_error = None
            try:
                result = await self.hass.async_add_executor_job(
                    functools.partial(self._issue_blocking, force)
                )
            except (AcmeError, DnsError) as err:
                self.last_error = str(err)
                await self._publish_status()
                self.hass.bus.async_fire(
                    EVENT_FAILED,
                    {"entry_id": self.entry.entry_id, "domains": self.domains, "error": self.last_error},
                )
                raise
            self.last_issued = datetime.datetime.now(datetime.timezone.utc).isoformat(
                timespec="seconds"
            )
            await self._publish_status()
            await self._call_reload_service()
            self.hass.bus.async_fire(
                EVENT_ISSUED,
                {
                    "entry_id": self.entry.entry_id,
                    "domains": self.domains,
                    "expiry_date": result.expiry_date,
                    "certificate_path": str(result.cert_path),
                },
            )
            return result

    def _issue_blocking(self, force: bool) -> IssueResult:
        config = entry_config(self.entry)
        try:
            return self.manager.issue(
                self.domains,
                dns_provider=config[CONF_DNS_PROVIDER],
                credentials=config.get(CONF_DNS_CREDENTIALS, {}),
                propagation_timeout=int(
                    config.get(CONF_PROPAGATION_TIMEOUT, DEFAULT_PROPAGATION_TIMEOUT)
                ),
                propagation_interval=int(
                    config.get(CONF_PROPAGATION_INTERVAL, DEFAULT_PROPAGATION_INTERVAL)
                ),
                force=force,
            )
        except (AcmeError, DnsError):
            raise
        except Exception as err:  # noqa: BLE001 - DNS providers raise many exception types
            raise AcmeError(describe_error(err)) from err

    async def _publish_status(self) -> None:
        self.async_set_updated_data(await self.hass.async_add_executor_job(self._status))

    async def _call_reload_service(self) -> None:
        service = str(entry_config(self.entry).get(CONF_RELOAD_SERVICE, "")).strip()
        if not service:
            return
        domain, _, name = service.partition(".")
        if not name or not self.hass.services.has_service(domain, name):
            _LOGGER.warning("Reload service %s is not registered", service)
            return
        await self.hass.services.async_call(domain, name, {}, blocking=False)
        _LOGGER.info("Called reload service %s after installing the certificate", service)
