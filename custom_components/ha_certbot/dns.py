"""DNS-01 challenge records, backed by dns-lexicon."""
from __future__ import annotations

import datetime
import json
import logging
import threading
import time
import warnings
from contextlib import ExitStack
from typing import Any

from .const import DEFAULT_PROPAGATION_INTERVAL, NETWORK_TIMEOUT

_LOGGER = logging.getLogger(__name__)

BASE_OPTION_DESTS = frozenset(
    {
        "action",
        "domain",
        "type",
        "name",
        "content",
        "ttl",
        "priority",
        "identifier",
        "log_level",
        "output",
        "help",
    }
)

FALLBACK_PROVIDERS = (
    "aliyun",
    "cloudflare",
    "desec",
    "digitalocean",
    "dnspod",
    "duckdns",
    "gandi",
    "godaddy",
    "henet",
    "hetzner",
    "inwx",
    "namecheap",
    "ovh",
    "qcloud",
    "route53",
    "transip",
    "vultr",
)


class DnsError(Exception):
    """A DNS record operation failed."""


def _lexicon() -> tuple[Any, ...]:
    """Import lexicon lazily so the integration still loads before requirements install."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from lexicon._private.discovery import find_providers, load_provider_module
        from lexicon._private.parser import generate_base_provider_parser
        from lexicon.client import Client
        from lexicon.config import ConfigResolver

    return Client, ConfigResolver, find_providers, load_provider_module, generate_base_provider_parser


def _dnspython() -> tuple[Any, ...]:
    import dns.exception
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.resolver

    return dns.exception, dns.message, dns.query, dns.rdatatype, dns.resolver


def available_providers() -> list[str]:
    """Return every DNS provider dns-lexicon ships."""
    try:
        _, _, find_providers, _, _ = _lexicon()
    except ImportError:
        _LOGGER.warning("dns-lexicon unavailable, using built-in provider list")
        return list(FALLBACK_PROVIDERS)
    return find_providers()


def provider_options(provider: str) -> list[tuple[str, str]]:
    """Return the credential options a provider accepts, read from its own parser metadata."""
    _, _, _, load_provider_module, generate_base_provider_parser = _lexicon()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        parser = generate_base_provider_parser()
        load_provider_module(provider).Provider.configure_parser(parser)
    options: list[tuple[str, str]] = []
    for action in parser._actions:
        if not action.option_strings or action.dest in BASE_OPTION_DESTS:
            continue
        options.append((action.dest, action.help or action.dest))
    return options


def check_credentials(provider: str, domain: str, credentials: dict[str, str]) -> None:
    """Authenticate against the provider without touching any record."""
    with DnsChallenge(provider, credentials) as challenge:
        challenge.authenticate(domain)


def _bounded_provider(name: str, base: type) -> type:
    import requests

    if name == "aliyun":
        from lexicon._private.providers.aliyun import ALIYUN_DNS_API_ENDPOINT

        class AliyunProvider(base):
            def _build_signature_parameters(self):
                parameters = super()._build_signature_parameters()
                # Lexicon 3.26.0 emits both +00:00 and Z, which is not a UTC timestamp.
                parameters["Timestamp"] = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                return parameters

            def _request(self, action="GET", url="/", data=None, query_params=None):
                try:
                    response = requests.request(
                        "GET", ALIYUN_DNS_API_ENDPOINT, params=query_params,
                        timeout=NETWORK_TIMEOUT,
                    )
                    response.raise_for_status()
                    return response.json()
                except requests.RequestException as err:
                    status = err.response.status_code if err.response is not None else "network error"
                    raise DnsError(f"Aliyun DNS request failed ({status})") from None

        return AliyunProvider

    if name == "cloudflare":
        class CloudflareProvider(base):
            def _request(self, action="GET", url="/", data=None, query_params=None):
                headers = {"Content-Type": "application/json"}
                if self._get_provider_option("auth_username"):
                    headers["X-Auth-Email"] = self._get_provider_option("auth_username")
                    headers["X-Auth-Key"] = self._get_provider_option("auth_token")
                else:
                    headers["Authorization"] = f"Bearer {self._get_provider_option('auth_token')}"
                response = requests.request(
                    action, self.api_endpoint + url, params=query_params or {},
                    data=json.dumps(data or {}), headers=headers, timeout=NETWORK_TIMEOUT,
                )
                response.raise_for_status()
                return response.json()

        return CloudflareProvider

    return base


class DnsChallenge:
    """Creates and removes the TXT records of one issuance, one client per zone."""

    def __init__(self, provider: str, credentials: dict[str, str]) -> None:
        self.provider = provider
        self.credentials = {key: value for key, value in credentials.items() if value}
        self._stack = ExitStack()
        self._operations: dict[str, Any] = {}
        self._created: list[tuple[str, str, str, str]] = []

    def __enter__(self) -> "DnsChallenge":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
        try:
            self.cleanup()
        finally:
            self._stack.close()
        return False

    def authenticate(self, domain: str) -> None:
        """Open a session for the zone, which makes the provider verify the credentials."""
        self._session(domain)

    @staticmethod
    def _records(operations: Any, name: str, value: str) -> list[dict[str, Any]]:
        return [
            record for record in operations.list_records("TXT", name, value)
            if str(record["name"]).rstrip(".").lower() == name.rstrip(".").lower()
            and str(record["content"]).strip('"') == value
            and record["type"] == "TXT"
        ]

    def create_txt(self, zone: str, name: str, value: str) -> None:
        operations = self._session(zone)
        if self._records(operations, name, value):
            return
        if operations.create_record("TXT", name, value) is False:
            raise DnsError(f"DNS provider refused to create TXT record {name}")
        records = self._records(operations, name, value)
        if len(records) != 1 or not records[0].get("id"):
            raise DnsError(f"Cannot identify the new TXT record {name}; check it manually before retrying")
        self._created.append((zone, name, value, str(records[0]["id"])))
        _LOGGER.debug("TXT %s created for zone %s", name, zone)

    def cleanup(self) -> None:
        for zone, name, value, identifier in reversed(self._created):
            try:
                operations = self._session(zone)
                records = self._records(operations, name, value)
                if not any(str(record["id"]) == identifier for record in records):
                    continue
                if operations.delete_record(
                    identifier=identifier, rtype="TXT", name=name, content=value
                ) is False:
                    raise DnsError("DNS provider refused to delete the TXT record")
            except Exception:
                _LOGGER.warning("Could not remove TXT record %s from zone %s", name, zone)
        self._created.clear()

    def _session(self, zone: str) -> Any:
        if zone not in self._operations:
            client_cls, resolver_cls, _, _, _ = _lexicon()
            resolver = resolver_cls().with_dict({
                "provider_name": self.provider, "domain": zone,
                "resolve_zone_name": True, self.provider: self.credentials,
            })
            client = client_cls(resolver)
            client.provider_class = _bounded_provider(self.provider, client.provider_class)
            self._operations[zone] = self._stack.enter_context(client)
        return self._operations[zone]


def nameserver_addresses(zone: str) -> list[str]:
    """Return the IPv4 addresses of the authoritative nameservers of a zone."""
    dns_exception, _, _, _, resolver = _dnspython()
    addresses: list[str] = []
    try:
        zone_name = resolver.zone_for_name(zone, lifetime=10)
        nameservers = resolver.resolve(zone_name, "NS", lifetime=10)
    except (dns_exception.DNSException, OSError):
        return addresses
    for nameserver in nameservers:
        try:
            records = resolver.resolve(nameserver.target, "A", lifetime=10)
        except (dns_exception.DNSException, OSError):
            continue
        addresses.extend(str(record) for record in records)
    return addresses


def published_txt_values(name: str, server: str | None = None) -> set[str] | None:
    """Return the TXT values published for a name, or None when the query failed."""
    dns_exception, message_mod, query_mod, rdatatype_mod, resolver = _dnspython()
    try:
        if server is None:
            answers = resolver.resolve(name, "TXT", lifetime=10)
            record_sets = list(answers.response.answer)
        else:
            query = message_mod.make_query(name, rdatatype_mod.TXT)
            response = query_mod.udp(query, server, timeout=5)
            record_sets = list(response.answer)
    except (dns_exception.DNSException, OSError):
        return None

    values: set[str] = set()
    for record_set in record_sets:
        if record_set.rdtype != rdatatype_mod.TXT:
            continue
        for record in record_set:
            values.add(
                "".join(part.decode(errors="replace") for part in record.strings)
            )
    return values


def wait_for_txt(
    name: str,
    values: set[str],
    zone: str,
    timeout: int,
    interval: int = DEFAULT_PROPAGATION_INTERVAL,
    *,
    cancel_event: threading.Event | None = None,
) -> bool:
    """Block until every answering authoritative nameserver publishes one of the values."""
    cancel_event = cancel_event or threading.Event()
    deadline = time.monotonic() + timeout
    servers = nameserver_addresses(zone)
    while not cancel_event.is_set():
        if servers:
            answering = 0
            published = 0
            for server in servers:
                found = published_txt_values(name, server)
                if found is None:
                    continue
                answering += 1
                if values & found:
                    published += 1
            if answering and published == answering:
                _LOGGER.debug("TXT %s visible on %d nameservers", name, answering)
                return True
        else:
            found = published_txt_values(name)
            if found and values & found:
                return True
        if time.monotonic() >= deadline:
            return False
        cancel_event.wait(min(interval, max(0, deadline - time.monotonic())))
    return False
