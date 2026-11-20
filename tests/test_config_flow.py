import asyncio
import importlib
import json
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from probatio.compat import install_as_voluptuous

from conftest import ROOT

install_as_voluptuous()
import probatio as vol


@pytest.fixture
def flow_module(monkeypatch):
    class Flow:
        def __init_subclass__(cls, **kwargs):
            super().__init_subclass__()

        async def async_set_unique_id(self, value):
            self.unique_id = value

        def _abort_if_unique_id_configured(self):
            pass

        def async_show_form(self, **kwargs):
            return {"type": "form", **kwargs}

        def async_show_menu(self, **kwargs):
            return {"type": "menu", **kwargs}

        def async_create_entry(self, **kwargs):
            return {"type": "create_entry", **kwargs}

        def async_abort(self, **kwargs):
            return {"type": "abort", **kwargs}

        def async_update_and_abort(self, entry, **kwargs):
            return {"type": "abort", "entry": entry, **kwargs}

        def _get_reconfigure_entry(self):
            return self.test_entry

        def _get_reauth_entry(self):
            return self.test_entry

    class Selector:
        def __init__(self, config):
            self.config = config

        def __call__(self, value):
            return value

        def serialize(self):
            kind = "select" if "options" in self.config else "text"
            return {"selector": {kind: self.config}}

    def register(name, **attributes):
        module = ModuleType(name)
        module.__dict__.update(attributes)
        monkeypatch.setitem(sys.modules, name, module)

    register("homeassistant")
    register("homeassistant.config_entries", ConfigEntry=object, ConfigFlow=Flow, OptionsFlow=Flow)
    register("homeassistant.core", callback=lambda func: func)
    register("homeassistant.data_entry_flow", FlowResult=dict)
    register("homeassistant.helpers")
    register("homeassistant.helpers.selector", SelectOptionDict=dict,
             SelectSelector=Selector, SelectSelectorConfig=dict,
             SelectSelectorMode=SimpleNamespace(DROPDOWN="dropdown"),
             TextSelector=Selector, TextSelectorConfig=dict,
             TextSelectorType=SimpleNamespace(TEXT="text", PASSWORD="password", URL="url", EMAIL="email"))
    name = "cert_test_component.config_flow"
    monkeypatch.delitem(sys.modules, name, raising=False)
    module = importlib.import_module(name)
    monkeypatch.setattr(module, "_credential_fields", lambda provider: [("auth_token", "Token"), ("auth_username", "Account")])
    monkeypatch.setattr(module, "available_providers", lambda: ["aliyun", "cloudflare"])
    monkeypatch.setattr(module, "check_credentials", Mock())
    return module


def flow(module, entry=None):
    result = module.HaCertbotConfigFlow()
    async def executor(function, *args):
        return function(*args)
    result.hass = SimpleNamespace(async_add_executor_job=executor,
        config_entries=SimpleNamespace(async_entries=lambda domain: []))
    if entry is not None:
        result.test_entry = entry
    return result


def settings(module, **extra):
    return {"domains": ["example.com", "*.example.com"], "acme_server": "letsencrypt",
        "acme_server_url": module.ACME_SERVERS["letsencrypt"], "dns_provider": "cloudflare", **extra}


def test_new_config_golden_path_and_serialization(flow_module):
    async def run():
        instance = flow(flow_module)
        result = await instance.async_step_user()
        assert result["step_id"] == "new_certificate"
        fields = vol.to_field_list(result["data_schema"], custom_serializer=lambda obj: obj.serialize() if hasattr(obj, "serialize") else vol.UNSUPPORTED)
        assert {field["name"] for field in fields} >= {"domains", "dns_provider"}
        await instance.async_step_new_certificate(settings(flow_module))
        result = await instance.async_step_credentials({"auth_token": "new-secret"})
        assert result["type"] == "create_entry"
        assert result["data"]["dns_credentials"] == {"auth_token": "new-secret"}
        flow_module.check_credentials.assert_called_once_with("cloudflare", "example.com", {"auth_token": "new-secret"})
    asyncio.run(run())


def test_builtin_ca_ignores_custom_url(flow_module):
    async def run():
        instance = flow(flow_module)
        await instance.async_step_user(settings(flow_module, acme_server_url=flow_module.ACME_SERVERS["letsencrypt_test"]))
        assert instance._settings["acme_server_url"] == flow_module.ACME_SERVERS["letsencrypt"]
    asyncio.run(run())


@pytest.mark.parametrize("url", ["", "http://example.com/directory", "https://user:secret@example.com/directory", "https://example.com:bad/directory", "not a URL", "https://example.com/directory#fragment"])
def test_invalid_custom_ca_url(flow_module, url):
    async def run():
        instance = flow(flow_module)
        result = await instance.async_step_user(settings(flow_module, acme_server="custom", acme_server_url=url))
        assert "acme_server_url" in result["errors"]
    asyncio.run(run())


def test_custom_ca_ids_include_endpoint(flow_module):
    async def run():
        ids = []
        for url in (flow_module.ACME_SERVERS["letsencrypt"], flow_module.ACME_SERVERS["letsencrypt_test"]):
            instance = flow(flow_module)
            result = await instance.async_step_user(settings(flow_module, acme_server="custom", acme_server_url=url))
            ids.append(instance.unique_id)
            assert {"eab_kid", "eab_hmac_key"} <= {key.schema for key in result["data_schema"].schema}
        assert len(set(ids)) == 2
    asyncio.run(run())


@pytest.mark.parametrize("eab,success", [({}, True), ({"eab_kid": "kid"}, False), ({"eab_hmac_key": "hmac"}, False), ({"eab_kid": "kid", "eab_hmac_key": "hmac"}, True)])
def test_custom_eab_pair(flow_module, eab, success):
    async def run():
        instance = flow(flow_module)
        await instance.async_step_user(settings(flow_module, acme_server="custom"))
        result = await instance.async_step_credentials({"auth_token": "token", **eab})
        assert (result["type"] == "create_entry") is success
    asyncio.run(run())


@pytest.mark.parametrize("replace", [False, True])
def test_reconfigure_retains_or_replaces_credentials(flow_module, replace):
    async def run():
        entry = SimpleNamespace(data=settings(flow_module, dns_credentials={"auth_token": "old-secret", "auth_username": "old-user"}), options={"days": 20})
        instance = flow(flow_module, entry)
        result = await instance.async_step_reconfigure()
        assert "old-secret" not in repr(result["data_schema"].schema)
        result = await instance.async_step_credentials({"auth_token": "new-secret", "replace_credentials": replace})
        assert result["entry"] is entry
        expected = {"auth_token": "new-secret"}
        if not replace:
            expected["auth_username"] = "old-user"
        assert result["data_updates"]["dns_credentials"] == expected
        assert result["options"] == {"days": 20}
        assert entry.data["dns_credentials"]["auth_token"] == "old-secret"
    asyncio.run(run())


def test_reauth_blank_secrets_keeps_eab_and_credentials(flow_module):
    async def run():
        entry = SimpleNamespace(data=settings(flow_module, acme_server="zerossl", dns_credentials={"auth_token": "old-secret"}, eab_kid="kid", eab_hmac_key="hmac"), options={})
        instance = flow(flow_module, entry)
        await instance.async_step_reauth(entry.data)
        result = await instance.async_step_credentials({"auth_token": "", "eab_kid": "kid", "eab_hmac_key": ""})
        assert result["data_updates"]["dns_credentials"]["auth_token"] == "old-secret"
        assert result["data_updates"]["eab_hmac_key"] == "hmac"
    asyncio.run(run())


def test_authentication_error_is_redacted_and_does_not_update(flow_module, caplog):
    async def run():
        entry = SimpleNamespace(data=settings(flow_module, dns_credentials={"auth_token": "old-secret"}), options={})
        instance = flow(flow_module, entry)
        await instance.async_step_reconfigure()
        flow_module.check_credentials.side_effect = RuntimeError("old-secret new-secret https://example.com/?signature=unknown")
        result = await instance.async_step_credentials({"auth_token": "new-secret"})
        detail = result["description_placeholders"]["detail"]
        assert result["errors"]["base"] == "cannot_authenticate"
        assert all(secret not in detail + caplog.text for secret in ("old-secret", "new-secret", "signature=unknown"))
        assert entry.data["dns_credentials"]["auth_token"] == "old-secret"
    asyncio.run(run())


@pytest.mark.parametrize("disabled", [False, True])
def test_legacy_import_requires_disabled_entry(flow_module, disabled):
    async def run():
        entry = SimpleNamespace(entry_id="old-entry", title="Old certificate", disabled_by="user" if disabled else None,
            data=settings(flow_module, dns_credentials={"auth_token": "old-secret"}), options={"days": 20})
        instance = flow(flow_module)
        instance.hass.config_entries.async_entries = lambda domain: [entry]
        menu = await instance.async_step_user()
        assert "migrate" in menu["menu_options"]
        result = await instance.async_step_migrate({"legacy_entry_id": entry.entry_id})
        if disabled:
            assert result["data"]["legacy_entry_id"] == entry.entry_id
            assert result["data"]["days"] == 20
            assert result["data"]["dns_credentials"] == entry.data["dns_credentials"]
        else:
            assert result["errors"]["base"] == "legacy_must_be_disabled"
    asyncio.run(run())


def test_translation_keys_match():
    english = json.loads((ROOT / "strings.json").read_text())
    chinese = json.loads((ROOT / "translations/zh-Hans.json").read_text())
    def keys(value, prefix=""):
        return {prefix + key for key in value} | set().union(*(
            keys(item, prefix + key + ".") for key, item in value.items() if isinstance(item, dict)
        ))
    assert keys(english) == keys(chinese)
    assert json.loads((ROOT / "translations/en.json").read_text()) == english
