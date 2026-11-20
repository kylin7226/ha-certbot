"""Config flow for ha-certbot."""
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

from .acme import entry_unique_id, normalize_server_url, parse_domains
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
    CONF_LEGACY_ENTRY_ID,
    LEGACY_DOMAIN,
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
from .errors import redact

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


class HaCertbotConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the setup of one certificate."""

    VERSION = 2

    def __init__(self) -> None:
        """Keep the first step's answers for the credentials step."""
        self._domains: list[str] = []
        self._settings: dict[str, Any] = {}
        self._detail = ""
        self._editing_entry: ConfigEntry | None = None

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        self._editing_entry = self._get_reconfigure_entry()
        self._settings = {**self._editing_entry.data, **self._editing_entry.options}
        self._domains = parse_domains(self._settings[CONF_DOMAINS])
        return await self.async_step_credentials(user_input)

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> FlowResult:
        self._editing_entry = self._get_reauth_entry()
        self._settings = {**self._editing_entry.data, **self._editing_entry.options}
        self._domains = parse_domains(self._settings[CONF_DOMAINS])
        return await self.async_step_credentials()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Ask for the domains, the CA and the DNS provider."""
        if user_input is None and self.hass.config_entries.async_entries(LEGACY_DOMAIN):
            return self.async_show_menu(step_id="user", menu_options=["new_certificate", "migrate"])
        return await self.async_step_new_certificate(user_input)

    async def async_step_new_certificate(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
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
                    try:
                        server_url = normalize_server_url(
                            custom_url if server == CUSTOM_SERVER else ACME_SERVERS[server]
                        )
                    except ValueError:
                        errors[CONF_ACME_SERVER_URL] = "invalid_server_url"
                    else:
                        await self.async_set_unique_id(entry_unique_id(server_url, domains[0]))
                        self._abort_if_unique_id_configured()
                        self._domains = domains
                        self._settings = {
                            **user_input,
                            CONF_DOMAINS: domains,
                            CONF_ACME_SERVER_URL: server_url,
                        }
                        return await self.async_step_credentials()

        values = user_input or {}
        providers = await self.hass.async_add_executor_job(available_providers)
        return self.async_show_form(
            step_id="new_certificate",
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
                        _option_list((name, name) for name in providers),
                        custom_value=True,
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_migrate(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        entries = {entry.entry_id: entry for entry in self.hass.config_entries.async_entries(LEGACY_DOMAIN)}
        if not entries:
            return self.async_abort(reason="no_legacy_entries")
        errors: dict[str, str] = {}
        if user_input is not None:
            entry = entries.get(user_input[CONF_LEGACY_ENTRY_ID])
            if entry is None:
                errors["base"] = "legacy_not_found"
            elif not entry.disabled_by:
                errors["base"] = "legacy_must_be_disabled"
            else:
                data = {**entry.data, **entry.options}
                try:
                    domains = parse_domains(data[CONF_DOMAINS])
                    server_url = normalize_server_url(
                        data.get(CONF_ACME_SERVER_URL) or ACME_SERVERS[data[CONF_ACME_SERVER]]
                    )
                    if not data.get(CONF_DNS_PROVIDER) or not data.get(CONF_DNS_CREDENTIALS):
                        raise ValueError("missing DNS settings")
                except (KeyError, ValueError):
                    errors["base"] = "invalid_legacy_config"
                else:
                    await self.async_set_unique_id(entry_unique_id(server_url, domains[0]))
                    self._abort_if_unique_id_configured()
                    data.update({CONF_DOMAINS: domains, CONF_ACME_SERVER_URL: server_url,
                                 CONF_LEGACY_ENTRY_ID: entry.entry_id})
                    return self.async_create_entry(title=entry.title, data=data)
        return self.async_show_form(
            step_id="migrate", errors=errors,
            data_schema=vol.Schema({vol.Required(CONF_LEGACY_ENTRY_ID): _selector(
                _option_list((entry.entry_id, entry.title) for entry in entries.values())
            )}),
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

        existing = self._settings.get(CONF_DNS_CREDENTIALS, {})
        if user_input is not None:
            credentials = dict(existing) if self._editing_entry and not user_input.get("replace_credentials") else {}
            for name, _ in fields:
                if name not in user_input:
                    continue
                value = str(user_input[name]).strip()
                if value:
                    credentials[name] = value
                elif not _is_secret(name):
                    credentials.pop(name, None)
            eab_kid = str(user_input.get(CONF_EAB_KID, self._settings.get(CONF_EAB_KID, ""))).strip()
            eab_hmac_key = str(user_input.get(CONF_EAB_HMAC_KEY, "")).strip()
            if self._editing_entry and eab_kid and not eab_hmac_key:
                eab_hmac_key = self._settings.get(CONF_EAB_HMAC_KEY, "")

            if needs_eab and not (eab_kid and eab_hmac_key):
                errors[CONF_EAB_KID] = "eab_required"
            elif bool(eab_kid) != bool(eab_hmac_key):
                errors[CONF_EAB_KID] = "eab_pair_required"
            elif not credentials:
                errors["base"] = "credentials_required"
            else:
                self._detail = ""
                try:
                    for zone in dict.fromkeys(domain.removeprefix("*.") for domain in self._domains):
                        await self.hass.async_add_executor_job(
                            check_credentials, provider, zone, credentials
                        )
                except Exception as err:
                    self._detail = redact(str(err), (
                        *existing.values(), *credentials.values(), eab_kid, eab_hmac_key
                    ))[:ERROR_DETAIL_LIMIT]
                    _LOGGER.warning("DNS credentials for %s were rejected: %s", provider, self._detail)
                    errors["base"] = "cannot_authenticate"
                else:
                    updates = {
                        CONF_DNS_CREDENTIALS: credentials,
                        CONF_EAB_KID: eab_kid, CONF_EAB_HMAC_KEY: eab_hmac_key,
                    }
                    if self._editing_entry:
                        options = {key: value for key, value in self._editing_entry.options.items() if key not in updates}
                        return self.async_update_and_abort(
                            self._editing_entry, data_updates=updates, options=options
                        )
                    return self.async_create_entry(
                        title=f"{self._domains[0]} ({ACME_SERVER_LABELS.get(server, server)})",
                        data={**self._settings, **updates},
                    )

        schema: dict[Any, Any] = {}
        if self._editing_entry:
            schema[vol.Optional("replace_credentials", default=False)] = bool
        for name, _description in fields:
            description = {} if _is_secret(name) else {"suggested_value": existing.get(name, "")}
            schema[vol.Optional(name, description=description)] = _text(
                TextSelectorType.PASSWORD if _is_secret(name) else TextSelectorType.TEXT
            )
        if needs_eab or server == CUSTOM_SERVER:
            schema[vol.Optional(CONF_EAB_KID, description={
                "suggested_value": self._settings.get(CONF_EAB_KID, "")
            })] = str
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
    def async_get_options_flow(config_entry: ConfigEntry) -> HaCertbotOptionsFlow:
        """Return the options flow handler."""
        return HaCertbotOptionsFlow()


class HaCertbotOptionsFlow(OptionsFlow):
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
