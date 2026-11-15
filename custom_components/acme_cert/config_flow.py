"""Config flow for the ACME certificate integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .acme import parse_domains
from .const import (
    ACME_SERVERS,
    ACME_SERVER_LABELS,
    CONF_ACME_SERVER,
    CONF_ACME_SERVER_URL,
    CONF_AUTO_RENEW,
    CONF_CHECK_HOURS,
    CONF_DAYS,
    CONF_DNS_CREDENTIALS,
    CONF_DNS_PROVIDER,
    CONF_DOMAINS,
    CONF_EAB_HMAC_KEY,
    CONF_EAB_KID,
    CONF_EMAIL,
    CONF_KEYLENGTH,
    CONF_PROPAGATION_INTERVAL,
    CONF_PROPAGATION_TIMEOUT,
    CONF_RELOAD_SERVICE,
    CUSTOM_SERVER,
    DEFAULT_ACME_SERVER,
    DEFAULT_AUTO_RENEW,
    DEFAULT_CHECK_HOURS,
    DEFAULT_DAYS,
    DEFAULT_DNS_PROVIDER,
    DEFAULT_KEYLENGTH,
    DEFAULT_PROPAGATION_INTERVAL,
    DEFAULT_PROPAGATION_TIMEOUT,
    DOMAIN,
    EAB_REQUIRED_SERVERS,
    KEYLENGTH_OPTIONS,
)
from .dns import available_providers, check_credentials, provider_options

_LOGGER = logging.getLogger(__name__)

SECRET_HINTS = ("token", "secret", "password", "key", "credential")
GENERIC_CREDENTIAL_FIELDS = (
    ("auth_username", "account name or user name"),
    ("auth_token", "API token"),
)
ERROR_DETAIL_LIMIT = 200


def _option_list(pairs: Any) -> list[SelectOptionDict]:
    return [SelectOptionDict(value=str(value), label=str(label)) for value, label in pairs]


def _selector(options: list[SelectOptionDict], custom_value: bool = False) -> SelectSelector:
    return SelectSelector(
        SelectSelectorConfig(
            options=options, mode=SelectSelectorMode.DROPDOWN, custom_value=custom_value
        )
    )


def _text(field_type: TextSelectorType = TextSelectorType.TEXT) -> TextSelector:
    return TextSelector(TextSelectorConfig(type=field_type))


def _is_secret(name: str) -> bool:
    return any(hint in name for hint in SECRET_HINTS)


def _credential_fields(provider: str) -> list[tuple[str, str]]:
    """Credential fields of a provider, falling back to the generic pair."""
    try:
        fields = provider_options(provider)
    except ImportError:
        _LOGGER.warning("dns-lexicon is unavailable, using generic credential fields")
        fields = []
    return fields or list(GENERIC_CREDENTIAL_FIELDS)


def _suggested_domains(values: dict[str, Any]) -> str:
    domains = values.get(CONF_DOMAINS, "")
    if isinstance(domains, (list, tuple)):
        return ", ".join(str(domain) for domain in domains)
    return str(domains)


class AcmeCertConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the setup of one certificate."""

    VERSION = 1

    def __init__(self) -> None:
        """Keep the first step's answers for the credentials step."""
        self._domains: list[str] = []
        self._settings: dict[str, Any] = {}
        self._detail = ""

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Ask for the domains, the CA and the DNS provider."""
        errors: dict[str, str] = {}

        if user_input is not None:
            server = user_input[CONF_ACME_SERVER]
            custom_url = str(user_input.get(CONF_ACME_SERVER_URL, "")).strip()
            try:
                domains = await self.hass.async_add_executor_job(
                    parse_domains, user_input[CONF_DOMAINS]
                )
            except ValueError:
                errors[CONF_DOMAINS] = "invalid_domains"
            else:
                if server == CUSTOM_SERVER and not custom_url:
                    errors[CONF_ACME_SERVER_URL] = "server_url_required"
                else:
                    await self.async_set_unique_id(f"{server}|{domains[0]}")
                    self._abort_if_unique_id_configured()
                    self._domains = domains
                    self._settings = {
                        **user_input,
                        CONF_DOMAINS: domains,
                        CONF_ACME_SERVER_URL: custom_url or ACME_SERVERS[server],
                    }
                    return await self.async_step_credentials()

        values = user_input or {}
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_DOMAINS,
                        description={"suggested_value": _suggested_domains(values)},
                    ): str,
                    vol.Required(
                        CONF_ACME_SERVER,
                        default=values.get(CONF_ACME_SERVER, DEFAULT_ACME_SERVER),
                    ): _selector(_option_list(ACME_SERVER_LABELS.items())),
                    vol.Optional(
                        CONF_ACME_SERVER_URL,
                        description={"suggested_value": values.get(CONF_ACME_SERVER_URL, "")},
                    ): _text(TextSelectorType.URL),
                    vol.Optional(
                        CONF_EMAIL,
                        description={"suggested_value": values.get(CONF_EMAIL, "")},
                    ): _text(TextSelectorType.EMAIL),
                    vol.Required(
                        CONF_KEYLENGTH,
                        default=values.get(CONF_KEYLENGTH, DEFAULT_KEYLENGTH),
                    ): _selector(_option_list((item, item) for item in KEYLENGTH_OPTIONS)),
                    vol.Required(
                        CONF_DAYS, default=values.get(CONF_DAYS, DEFAULT_DAYS)
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=180)),
                    vol.Required(
                        CONF_DNS_PROVIDER,
                        default=values.get(CONF_DNS_PROVIDER, DEFAULT_DNS_PROVIDER),
                    ): _selector(
                        _option_list((name, name) for name in available_providers()),
                        custom_value=True,
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Ask for the DNS provider credentials and verify them."""
        errors: dict[str, str] = {}
        provider = self._settings[CONF_DNS_PROVIDER]
        server = self._settings[CONF_ACME_SERVER]
        needs_eab = server in EAB_REQUIRED_SERVERS
        fields = await self.hass.async_add_executor_job(_credential_fields, provider)

        if user_input is not None:
            credentials = {
                key: str(value).strip()
                for key, value in user_input.items()
                if key not in (CONF_EAB_KID, CONF_EAB_HMAC_KEY) and str(value).strip()
            }
            eab_kid = str(user_input.get(CONF_EAB_KID, "")).strip()
            eab_hmac_key = str(user_input.get(CONF_EAB_HMAC_KEY, "")).strip()

            if needs_eab and not (eab_kid and eab_hmac_key):
                errors[CONF_EAB_KID] = "eab_required"
            elif not credentials:
                errors["base"] = "credentials_required"
            else:
                zone = self._domains[0]
                if zone.startswith("*."):
                    zone = zone[2:]
                self._detail = ""
                try:
                    await self.hass.async_add_executor_job(
                        check_credentials, provider, zone, credentials
                    )
                except Exception as err:  # noqa: BLE001 - providers raise many exception types
                    _LOGGER.warning("DNS credentials for %s were rejected: %s", provider, err)
                    errors["base"] = "cannot_authenticate"
                    self._detail = str(err)[:ERROR_DETAIL_LIMIT]
                else:
                    data = {**self._settings, CONF_DNS_CREDENTIALS: credentials}
                    if eab_kid:
                        data[CONF_EAB_KID] = eab_kid
                        data[CONF_EAB_HMAC_KEY] = eab_hmac_key
                    return self.async_create_entry(
                        title=f"{self._domains[0]} ({ACME_SERVER_LABELS.get(server, server)})",
                        data=data,
                    )

        schema: dict[Any, Any] = {}
        for name, _description in fields:
            schema[vol.Optional(name)] = _text(
                TextSelectorType.PASSWORD if _is_secret(name) else TextSelectorType.TEXT
            )
        if needs_eab:
            schema[vol.Optional(CONF_EAB_KID)] = str
            schema[vol.Optional(CONF_EAB_HMAC_KEY)] = _text(TextSelectorType.PASSWORD)

        return self.async_show_form(
            step_id="credentials",
            data_schema=vol.Schema(schema),
            errors=errors,
            description_placeholders={
                "provider": provider,
                "fields": "\n".join(f"{name}: {text}" for name, text in fields),
                "detail": self._detail,
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> AcmeCertOptionsFlow:
        """Return the options flow handler."""
        return AcmeCertOptionsFlow()


class AcmeCertOptionsFlow(OptionsFlow):
    """Handle renewal, propagation and reload options."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(data=user_input)

        config = {**self.config_entry.data, **self.config_entry.options}
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_AUTO_RENEW,
                        default=config.get(CONF_AUTO_RENEW, DEFAULT_AUTO_RENEW),
                    ): bool,
                    vol.Optional(
                        CONF_DAYS, default=config.get(CONF_DAYS, DEFAULT_DAYS)
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=180)),
                    vol.Optional(
                        CONF_CHECK_HOURS,
                        default=config.get(CONF_CHECK_HOURS, DEFAULT_CHECK_HOURS),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=168)),
                    vol.Optional(
                        CONF_PROPAGATION_TIMEOUT,
                        default=config.get(
                            CONF_PROPAGATION_TIMEOUT, DEFAULT_PROPAGATION_TIMEOUT
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=10, max=3600)),
                    vol.Optional(
                        CONF_PROPAGATION_INTERVAL,
                        default=config.get(
                            CONF_PROPAGATION_INTERVAL, DEFAULT_PROPAGATION_INTERVAL
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=1, max=300)),
                    vol.Optional(
                        CONF_RELOAD_SERVICE,
                        description={"suggested_value": config.get(CONF_RELOAD_SERVICE, "")},
                    ): str,
                }
            ),
        )
