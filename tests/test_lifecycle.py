import asyncio
import importlib
from pathlib import Path
import sys
import threading
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from conftest import ROOT


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    def register(name, **attributes):
        module = ModuleType(name)
        module.__dict__.update(attributes)
        monkeypatch.setitem(sys.modules, name, module)
        return module

    class BaseCoordinator:
        def __class_getitem__(cls, item):
            return cls

        def __init__(self, hass, logger, *, config_entry, **kwargs):
            self.hass = hass
            self.data = None
            self.update_interval = kwargs.get("update_interval")
            config_entry.async_on_unload(self.async_shutdown)

        async def async_config_entry_first_refresh(self):
            self.data = await self._async_update_data()

        async def async_request_refresh(self):
            self.data = await self._async_update_data()

        async def async_shutdown(self):
            pass

        def async_set_updated_data(self, data):
            self.data = data

    register("homeassistant")
    register("homeassistant.config_entries", ConfigEntry=object)
    register("homeassistant.const", Platform=SimpleNamespace(SENSOR="sensor"))
    register("homeassistant.core", HomeAssistant=object, ServiceCall=object)
    register("homeassistant.exceptions", ConfigEntryError=type("ConfigEntryError", (Exception,), {}), ServiceValidationError=type("ServiceValidationError", (Exception,), {}))
    helpers = register("homeassistant.helpers")
    helpers.config_validation = SimpleNamespace(string=str, boolean=bool)
    register("homeassistant.helpers.update_coordinator", DataUpdateCoordinator=BaseCoordinator)
    for name in list(sys.modules):
        if name == "lifecycle_component" or name.startswith("lifecycle_component."):
            monkeypatch.delitem(sys.modules, name)
    package = register("lifecycle_component")
    package.__path__ = [str(ROOT)]
    init = importlib.import_module("lifecycle_component.__init__")
    coordinator_module = importlib.import_module("lifecycle_component.coordinator")

    class Hass:
        def __init__(self):
            self.data = {}
            self.config = SimpleNamespace(path=lambda *parts: str(tmp_path.joinpath(*parts)))
            self.config_entries = SimpleNamespace(async_forward_entry_setups=AsyncMock(), async_unload_platforms=AsyncMock(return_value=True))
            self.bus = SimpleNamespace(async_fire=Mock())
            self.services = SimpleNamespace(has_service=Mock(return_value=False), async_register=Mock(), async_call=AsyncMock())

        def async_add_executor_job(self, function, *args):
            return asyncio.get_running_loop().run_in_executor(None, function, *args)

    class Entry:
        def __init__(self, auto_renew=True):
            self.entry_id = "entry"
            self.title = "Certificate"
            self.data = {"acme_server": "letsencrypt", "domains": ["example.com"], "dns_provider": "aliyun", "auto_renew": auto_renew}
            self.options = {}
            self.tasks = set()
            self.async_on_unload = Mock()
            self.add_update_listener = Mock()

        def async_create_background_task(self, hass, target, name, eager_start=True):
            assert eager_start is False
            task = asyncio.create_task(target, name=name)
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            return task

    return SimpleNamespace(init=init, module=coordinator_module, Hass=Hass, Entry=Entry)


def manager_mock():
    manager = Mock()
    manager.certificate_status.return_value = {"status": "not_found"}
    manager.issue.return_value = SimpleNamespace(expiry_date="2027-01-01", cert_path=Path("fullchain.pem"))
    return manager


def test_setup_waits_for_platforms_before_starting_issuance(runtime, monkeypatch):
    async def run():
        hass, entry, manager = runtime.Hass(), runtime.Entry(), manager_mock()
        finished = threading.Event()
        result = manager.issue.return_value
        manager.issue.side_effect = lambda *args, **kwargs: (finished.set(), result)[1]
        monkeypatch.setattr(runtime.init, "CertificateManager", Mock(return_value=manager))

        async def forward(*args):
            manager.issue.assert_not_called()
            assert not entry.tasks

        hass.config_entries.async_forward_entry_setups.side_effect = forward
        assert await runtime.init.async_setup_entry(hass, entry)
        assert entry.tasks
        assert await asyncio.to_thread(finished.wait, 2)
        coordinator = hass.data["ha_certbot"]["entry"]
        settled = asyncio.Event()
        coordinator._issue_task.add_done_callback(lambda task: settled.set())
        await coordinator._issue_task
        await settled.wait()
        assert await runtime.init.async_unload_entry(hass, entry)
        assert "entry" not in hass.data["ha_certbot"]
        assert not entry.tasks
        hass.config_entries.async_unload_platforms.assert_awaited_once()
        hass.services.async_register.assert_called_once()

    asyncio.run(run())


def test_failed_setup_does_not_issue_or_leave_runtime(runtime, monkeypatch):
    async def run():
        hass, entry, manager = runtime.Hass(), runtime.Entry(), manager_mock()
        monkeypatch.setattr(runtime.init, "CertificateManager", Mock(return_value=manager))
        hass.config_entries.async_forward_entry_setups.side_effect = RuntimeError("platform failed")
        with pytest.raises(RuntimeError):
            await runtime.init.async_setup_entry(hass, entry)
        manager.issue.assert_not_called()
        assert not hass.data["ha_certbot"]
        assert not entry.tasks

    asyncio.run(run())


@pytest.mark.parametrize("status", ["not_found", "error", "expired", "renewal_required", "valid"])
def test_auto_renew_statuses(runtime, status):
    async def run():
        coordinator = runtime.module.HaCertbotCoordinator(runtime.Hass(), runtime.Entry(), manager_mock(), ["example.com"])
        assert coordinator._renewal_due({"status": status, "auto_renew": True}) is (status != "valid")
        assert not coordinator._renewal_due({"status": status, "auto_renew": False})
        await coordinator.async_shutdown()
        assert not coordinator._renewal_due({"status": status, "auto_renew": True})

    asyncio.run(run())


def test_cancelled_service_keeps_worker_guard_and_blocks_second_issue(runtime):
    async def run():
        hass, entry, manager = runtime.Hass(), runtime.Entry(), manager_mock()
        started, release, finished = threading.Event(), threading.Event(), threading.Event()
        result = manager.issue.return_value

        def issue(*args, **kwargs):
            started.set()
            release.wait(5)
            finished.set()
            return result

        manager.issue.side_effect = issue
        coordinator = runtime.module.HaCertbotCoordinator(hass, entry, manager, ["example.com"])
        task = asyncio.create_task(coordinator.async_issue())
        try:
            assert await asyncio.to_thread(started.wait, 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert coordinator.lock.locked() and not finished.is_set()
            with pytest.raises(runtime.module.AcmeError, match="already running"):
                await coordinator.async_issue()
        finally:
            release.set()
            await coordinator.async_shutdown()
        assert finished.is_set()
        assert not coordinator.lock.locked()
        hass.bus.async_fire.assert_not_called()
        hass.services.async_call.assert_not_called()

    asyncio.run(run())


def test_unload_waits_for_worker_and_no_late_publish(runtime):
    async def run():
        hass, entry, manager = runtime.Hass(), runtime.Entry(), manager_mock()
        started, release, cancelled, finished = [threading.Event() for _ in range(4)]

        def issue(*args, cancel_event, **kwargs):
            started.set()
            cancel_event.wait(5)
            cancelled.set()
            release.wait(5)
            finished.set()
            raise runtime.module.AcmeError("cancelled")

        manager.issue.side_effect = issue
        coordinator = runtime.module.HaCertbotCoordinator(hass, entry, manager, ["example.com"])
        hass.data["ha_certbot"] = {"entry": coordinator}
        task = asyncio.create_task(coordinator.async_issue())
        unload = None
        try:
            assert await asyncio.to_thread(started.wait, 2)
            unload = asyncio.create_task(runtime.init.async_unload_entry(hass, entry))
            assert await asyncio.to_thread(cancelled.wait, 2)
            assert not unload.done()
            assert coordinator.lock.locked()
            assert not finished.is_set()
            coordinator._issue_task.cancel()
            assert coordinator.lock.locked()
        finally:
            release.set()
            if unload is not None:
                assert await unload
            await asyncio.gather(task, return_exceptions=True)
        assert finished.is_set()
        assert coordinator._issue_task.done()
        assert "entry" not in hass.data["ha_certbot"]
        assert not coordinator.lock.locked()
        hass.bus.async_fire.assert_not_called()
        hass.services.async_call.assert_not_called()

    asyncio.run(run())


def test_failed_platform_unload_keeps_entry_operational(runtime):
    async def run():
        hass, entry = runtime.Hass(), runtime.Entry()
        coordinator = runtime.module.HaCertbotCoordinator(hass, entry, manager_mock(), ["example.com"])
        hass.data["ha_certbot"] = {"entry": coordinator}
        hass.config_entries.async_unload_platforms.return_value = False
        assert not await runtime.init.async_unload_entry(hass, entry)
        assert not coordinator._stopping
        assert hass.data["ha_certbot"]["entry"] is coordinator
        await coordinator.async_shutdown()

    asyncio.run(run())


def test_issuance_failure_is_reported_once_and_releases_guard(runtime):
    async def run():
        hass, entry, manager = runtime.Hass(), runtime.Entry(), manager_mock()
        manager.issue.side_effect = runtime.module.AcmeError("CA unavailable")
        coordinator = runtime.module.HaCertbotCoordinator(hass, entry, manager, ["example.com"])
        with pytest.raises(runtime.module.AcmeError):
            await coordinator.async_issue()
        assert not coordinator._issuing
        assert not coordinator.lock.locked()
        assert coordinator.last_error == "CA unavailable"
        hass.bus.async_fire.assert_called_once()
        await coordinator.async_shutdown()

    asyncio.run(run())


def test_errors_are_redacted_in_status_event_and_exception(runtime):
    async def run():
        hass, entry, manager = runtime.Hass(), runtime.Entry(), manager_mock()
        entry.data.update({"dns_credentials": {"auth_token": "secret/token"}, "eab_hmac_key": "hmac-secret"})
        manager.issue.side_effect = RuntimeError("secret%2Ftoken hmac-secret https://example.com/?signature=other")
        coordinator = runtime.module.HaCertbotCoordinator(hass, entry, manager, ["example.com"])
        with pytest.raises(runtime.module.AcmeError) as caught:
            await coordinator.async_issue()
        output = str(caught.value) + coordinator.last_error + repr(hass.bus.async_fire.call_args)
        assert all(secret not in output for secret in ("secret%2Ftoken", "hmac-secret", "signature=other"))
        assert caught.value.__suppress_context__
        await coordinator.async_shutdown()
    asyncio.run(run())


def test_config_updates_schedule_reload(runtime):
    async def run():
        hass, entry = runtime.Hass(), runtime.Entry()
        hass.config_entries.async_schedule_reload = Mock()
        await runtime.init._async_options_updated(hass, entry)
        hass.config_entries.async_schedule_reload.assert_called_once_with(entry.entry_id)
    asyncio.run(run())


def test_entry_version_migration_preserves_settings(runtime):
    async def run():
        hass, entry = runtime.Hass(), runtime.Entry()
        entry.version = 1
        entry.unique_id = "letsencrypt|example.com"
        original = dict(entry.data)
        hass.config_entries.async_entry_for_domain_unique_id = Mock(return_value=None)
        hass.config_entries.async_update_entry = Mock()
        assert await runtime.init.async_migrate_entry(hass, entry)
        kwargs = hass.config_entries.async_update_entry.call_args.kwargs
        assert kwargs["version"] == 2
        assert kwargs["unique_id"].endswith("|example.com")
        assert kwargs["unique_id"] != entry.unique_id
        assert entry.data == original
    asyncio.run(run())
