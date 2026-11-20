import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType
from unittest.mock import AsyncMock, Mock, patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from homeassistant.config_entries import ConfigEntries, ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.selector import Selector
import probatio

from custom_components.ha_certbot import async_setup_entry, async_unload_entry
from custom_components.ha_certbot import config_flow
from custom_components.ha_certbot.const import DOMAIN
from custom_components.ha_certbot.sensor import HaCertbotCertificateSensor


def serialize(form):
    fields = probatio.to_field_list(form["data_schema"], custom_serializer=lambda value:
        value.serialize() if isinstance(value, Selector) else probatio.UNSUPPORTED)
    assert fields
    return fields


async def main(config_dir):
    hass = HomeAssistant(config_dir)
    hass.config_entries = ConfigEntries(hass, {})
    flow = config_flow.HaCertbotConfigFlow()
    flow.hass = hass
    flow.handler = DOMAIN
    flow.flow_id = "smoke-new"
    flow.context = {"source": "user"}
    with patch.object(config_flow, "check_credentials") as authenticate:
        form = await flow.async_step_user()
        serialize(form)
        data = form["data_schema"]({
            "domains": "example.com,*.example.com", "acme_server": "letsencrypt",
            "dns_provider": "cloudflare", "keylength": "ec-256", "days": 30,
        })
        form = await flow.async_step_new_certificate(data)
        serialize(form)
        created = await flow.async_step_credentials(form["data_schema"]({"auth_token": "smoke-only"}))
        assert created["type"] == "create_entry"
        authenticate.assert_called_once()

        entry = ConfigEntry(
            domain=DOMAIN, title=created["title"], data=created["data"],
            options={"auto_renew": False}, version=2, minor_version=1,
            source="user", unique_id=flow.unique_id,
            discovery_keys=MappingProxyType({}), subentries_data=None,
        )
        with (
            patch.object(hass.config_entries, "async_setup", AsyncMock(return_value=True)),
            patch.object(hass.config_entries, "async_update_issues", Mock()),
        ):
            await hass.config_entries.async_add(entry)
        with (
            patch.object(hass.config_entries, "async_forward_entry_setups", AsyncMock()) as forward,
            patch.object(hass.config_entries, "async_unload_platforms", AsyncMock(return_value=True)),
            patch.object(hass.config_entries, "async_schedule_reload", Mock()) as reload_entry,
        ):
            assert await async_setup_entry(hass, entry)
            forward.assert_awaited_once()
            sensor = HaCertbotCertificateSensor(hass.data[DOMAIN][entry.entry_id])
            assert sensor.native_value == "not_found"
            assert hass.services.has_service(DOMAIN, "issue_certificate")
            options = config_flow.HaCertbotOptionsFlow()
            options.hass = hass
            options.handler = entry.entry_id
            serialize(await options.async_step_init())
            update = config_flow.HaCertbotConfigFlow()
            update.hass = hass
            update.handler = DOMAIN
            update.flow_id = "smoke-update"
            update.context = {"source": "reconfigure", "entry_id": entry.entry_id}
            form = await update.async_step_reconfigure()
            assert "smoke-only" not in repr(serialize(form))
            result = await update.async_step_credentials({"auth_token": "replacement-only"})
            assert result["type"] == "abort"
            await hass.async_block_till_done()
            assert entry.data["dns_credentials"]["auth_token"] == "replacement-only"
            reload_entry.assert_called_once_with(entry.entry_id)
            assert await async_unload_entry(hass, entry)
    await hass.async_stop()


if __name__ == "__main__":
    with TemporaryDirectory(prefix="ha-certbot-smoke-") as directory:
        asyncio.run(main(directory))
    print("Home Assistant import, setup/unload, forms, and reconfiguration smoke passed")
