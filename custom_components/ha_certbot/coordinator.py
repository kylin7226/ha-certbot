"""Certificate status polling and renewal scheduling."""
from __future__ import annotations

import asyncio
import datetime
import functools
import logging
import threading
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
    CONF_EAB_KID,
    CONF_EAB_HMAC_KEY,
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
    STATUS_ERROR,
    STATUS_EXPIRED,
    STATUS_NOT_FOUND,
    STATUS_RENEWAL_REQUIRED,
)
from .dns import DnsError
from .errors import redact

_LOGGER = logging.getLogger(__name__)


def entry_config(entry: ConfigEntry) -> dict[str, Any]:
    """Config entry data with the values from the options flow applied on top."""
    return {**entry.data, **entry.options}


class HaCertbotCoordinator(DataUpdateCoordinator[dict[str, Any]]):
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
        self._issue_task: asyncio.Task[IssueResult] | None = None
        self._cancel_event = threading.Event()
        self._started = False
        self._stopping = False
        self.last_error: str | None = None
        self.last_issued: str | None = None
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN}.{entry.entry_id}",
            update_interval=self._interval(entry_config(entry)),
        )

    @staticmethod
    def _interval(config: dict[str, Any]) -> datetime.timedelta:
        hours = int(config.get(CONF_CHECK_HOURS, DEFAULT_CHECK_HOURS))
        return datetime.timedelta(hours=hours)

    async def _async_update_data(self) -> dict[str, Any]:
        data = await self.hass.async_add_executor_job(self._status)
        if self._started and self._renewal_due(data):
            self._start_issue()
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
        if self._stopping or not data["auto_renew"] or self._issuing:
            return False
        return data["status"] in (STATUS_RENEWAL_REQUIRED, STATUS_EXPIRED, STATUS_NOT_FOUND, STATUS_ERROR)

    @property
    def _issuing(self) -> bool:
        return self._issue_task is not None and not self._issue_task.done()

    def start(self) -> None:
        self._started = True
        if self._renewal_due(self.data):
            self._start_issue()

    def _start_issue(self, force: bool = False) -> asyncio.Task[IssueResult]:
        if self._stopping:
            raise AcmeError("certificate entry is unloading")
        if self._issuing:
            raise AcmeError("another certificate operation is already running")
        self._cancel_event.clear()
        self._issue_task = self.entry.async_create_background_task(
            self.hass, self._async_issue(force), f"{DOMAIN} issue {self.entry.entry_id}",
            eager_start=False,
        )
        self._issue_task.add_done_callback(self._issue_done)
        return self._issue_task

    @staticmethod
    def _issue_done(task: asyncio.Task[IssueResult]) -> None:
        if not task.cancelled() and (error := task.exception()) is not None:
            _LOGGER.error("Certificate operation failed (%s)", type(error).__name__)

    async def async_issue(self, force: bool = False) -> IssueResult:
        task = self._start_issue(force)
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            self._cancel_event.set()
            raise

    async def async_shutdown(self) -> None:
        self._stopping = True
        self._cancel_event.set()
        await super().async_shutdown()
        task = self._issue_task
        if task is not None and not task.done():
            task.cancel()
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
                except (AcmeError, DnsError):
                    break

    async def _async_issue(self, force: bool) -> IssueResult:
        async with self.lock:
            self.last_error = None
            # HA cancels registered executor futures at shutdown, before their threads stop.
            worker = asyncio.get_running_loop().run_in_executor(
                None, functools.partial(self._issue_blocking, force)
            )
            try:
                result = await asyncio.shield(worker)
            except asyncio.CancelledError:
                self._cancel_event.set()
                # Cancelling an asyncio waiter does not stop its executor thread.
                while not worker.done():
                    try:
                        await asyncio.shield(worker)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break
                if not worker.cancelled():
                    worker.exception()
                raise
            except (AcmeError, DnsError) as err:
                if self._cancel_event.is_set():
                    raise asyncio.CancelledError from err
                self.last_error = str(err)
                await self._publish_status()
                self.hass.bus.async_fire(
                    EVENT_FAILED,
                    {"entry_id": self.entry.entry_id, "domains": self.domains, "error": self.last_error},
                )
                raise
            if self._stopping or self._cancel_event.is_set():
                raise asyncio.CancelledError
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
                cancel_event=self._cancel_event,
            )
        except Exception as err:
            secrets = (
                *config.get(CONF_DNS_CREDENTIALS, {}).values(),
                config.get(CONF_EAB_KID, ""), config.get(CONF_EAB_HMAC_KEY, ""),
            )
            error_type = DnsError if isinstance(err, DnsError) else AcmeError
            raise error_type(redact(describe_error(err), secrets)) from None

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
