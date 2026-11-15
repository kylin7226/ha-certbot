"""DNS-01 challenge records, backed by dns-lexicon."""
from __future__ import annotations

import logging
import time
import warnings
from contextlib import ExitStack
from typing import Any

from .const import DEFAULT_PROPAGATION_INTERVAL

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


class DnsChallenge:
    """Creates and removes the TXT records of one issuance, one client per zone."""

    def __init__(self, provider: str, credentials: dict[str, str]) -> None:
        self.provider = provider
        self.credentials = {key: value for key, value in credentials.items() if value}
        self._stack = ExitStack()
        self._operations: dict[str, Any] = {}
        self._created: list[tuple[str, str, str]] = []

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

    def create_txt(self, zone: str, name: str, value: str) -> None:
        self._session(zone).create_record("TXT", name, value)
        self._created.append((zone, name, value))
        _LOGGER.debug("TXT %s created for zone %s", name, zone)

    def cleanup(self) -> None:
        for zone, name, value in reversed(self._created):
            try:
                self._session(zone).delete_record(rtype="TXT", name=name, content=value)
            except Exception:  # noqa: BLE001 - leftover records must not fail issuance
                _LOGGER.warning("Could not remove TXT record %s from zone %s", name, zone)
        self._created.clear()

    def _session(self, zone: str) -> Any:
        if zone not in self._operations:
            client_cls, resolver_cls, _, _, _ = _lexicon()
            config = {"provider_name": self.provider, "domain": zone, **self.credentials}
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                resolver = resolver_cls().with_legacy_dict(config)
            self._operations[zone] = self._stack.enter_context(client_cls(resolver))
        return self._operations[zone]


def nameserver_addresses(zone: str) -> list[str]:
    """Return the IPv4 addresses of the authoritative nameservers of a zone."""
    dns_exception, _, _, _, resolver = _dnspython()
    addresses: list[str] = []
    try:
        nameservers = resolver.resolve(zone, "NS", lifetime=10)
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
) -> bool:
    """Block until every answering authoritative nameserver publishes one of the values."""
    deadline = time.monotonic() + timeout
    servers = nameserver_addresses(zone)
    while True:
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
        time.sleep(interval)
