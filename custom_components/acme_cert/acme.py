"""Certificate issuance over ACME (RFC 8555), using certbot's acme library."""
from __future__ import annotations

import datetime
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from .const import (
    ACCOUNTS_DIR_NAME,
    CERT_SUFFIX_CA,
    CERT_SUFFIX_CERT,
    CERT_SUFFIX_FULLCHAIN,
    CERT_SUFFIX_KEY,
    DATA_DIR_NAME,
    DEFAULT_KEYLENGTH,
    DEFAULT_PROPAGATION_INTERVAL,
    DEFAULT_PROPAGATION_TIMEOUT,
    LIVE_DIR_NAME,
    NETWORK_TIMEOUT,
    ORDER_TIMEOUT,
    SSL_DIR_NAME,
    STATUS_ERROR,
    STATUS_EXPIRED,
    STATUS_NOT_FOUND,
    STATUS_RENEWAL_REQUIRED,
    STATUS_VALID,
    USER_AGENT,
)
from .dns import DnsChallenge, DnsError, wait_for_txt

_LOGGER = logging.getLogger(__name__)

DOMAIN_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)
CERTIFICATE_BLOCK_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\r?\n?", re.S
)
DNS01_CHALLENGE = "dns-01"
ACCOUNT_KEY_SIZE = 2048
EC_CURVES = {256: ec.SECP256R1, 384: ec.SECP384R1}


class AcmeError(Exception):
    """A certificate operation failed."""


def resolve_data_dir(hass: Any) -> Path:
    """Return the directory holding account keys, CSRs and issued certificates."""
    return Path(hass.config.path(DATA_DIR_NAME))


def resolve_ssl_dir(hass: Any) -> Path:
    """Return the shared SSL directory when present, otherwise one below the config dir."""
    shared = Path("/ssl")
    return shared if shared.is_dir() else Path(hass.config.path(SSL_DIR_NAME))


def parse_domains(raw: Any) -> list[str]:
    """Split a comma separated domain list and validate every entry."""
    items = raw if isinstance(raw, (list, tuple)) else str(raw).replace("\n", ",").split(",")
    domains: list[str] = []
    for item in items:
        domain = str(item).strip().lower().rstrip(".")
        if not domain or domain in domains:
            continue
        bare = domain[2:] if domain.startswith("*.") else domain
        if not DOMAIN_RE.fullmatch(bare):
            raise ValueError(f"invalid domain name: {domain}")
        domains.append(domain)
    if not domains:
        raise ValueError("no domain name given")
    return domains


def generate_private_key(keylength: str) -> Any:
    """Create a certificate or account private key for the requested key length."""
    if keylength.startswith("ec-"):
        bits = int(keylength.split("-", 1)[1])
        if bits not in EC_CURVES:
            raise ValueError(f"unsupported EC key length: {keylength}")
        return ec.generate_private_key(EC_CURVES[bits]())
    size = int(keylength)
    return rsa.generate_private_key(public_exponent=65537, key_size=size)


def write_private_key(path: Path, key: Any) -> None:
    """Store a private key as unencrypted PKCS#8 PEM, readable by root only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def load_private_key(path: Path) -> Any:
    """Read back a private key written by write_private_key."""
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def build_csr(key: Any, domains: list[str]) -> bytes:
    """Build a CSR carrying every domain in the subject alternative name extension."""
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in domains]),
            critical=False,
        )
    )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def split_fullchain(pem: str) -> tuple[str, str]:
    """Split a full chain into the leaf certificate and the issuing chain."""
    blocks = CERTIFICATE_BLOCK_RE.findall(pem)
    if not blocks:
        raise AcmeError("the CA returned no certificate")
    return blocks[0], "".join(blocks[1:])


def certificate_info(pem_path: Path) -> dict[str, Any]:
    """Describe an installed certificate without contacting anyone."""
    leaf_pem, _ = split_fullchain(pem_path.read_text(encoding="utf-8"))
    certificate = x509.load_pem_x509_certificate(leaf_pem.encode("utf-8"))
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = [
            attribute.value
            for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ]
    not_after = certificate.not_valid_after_utc
    remaining = not_after - datetime.datetime.now(datetime.timezone.utc)
    return {
        "domains": names,
        "expiry_date": not_after.isoformat(),
        "days_remaining": remaining.days,
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_number": format(certificate.serial_number, "x"),
    }


def describe_error(exc: Exception) -> str:
    """Turn an acme library exception into a message worth showing to the user."""
    failed_authzrs = getattr(exc, "failed_authzrs", None)
    if failed_authzrs:
        details = []
        for authzr in failed_authzrs:
            for challenge in authzr.body.challenges:
                if challenge.error is not None:
                    reason = challenge.error.description or challenge.error.code or "challenge failed"
                    details.append(f"{authzr.body.identifier.value}: {reason}")
        if details:
            return "; ".join(details)
    description = getattr(exc, "description", None)
    code = getattr(exc, "code", None)
    if description:
        return f"{code}: {description}" if code else str(description)
    return str(exc)


def _write(path: Path, content: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


@dataclass
class IssueResult:
    """What an issuance produced."""

    domains: list[str]
    cert_path: Path
    key_path: Path
    expiry_date: str
    days_remaining: int
    issuer: str


class CertificateManager:
    """Holds the account state of one CA and issues certificates for one config entry."""

    def __init__(
        self,
        *,
        data_dir: Path,
        ssl_dir: Path,
        server: str,
        server_url: str,
        email: str = "",
        keylength: str = DEFAULT_KEYLENGTH,
        eab_kid: str = "",
        eab_hmac_key: str = "",
    ) -> None:
        self.data_dir = Path(data_dir)
        self.ssl_dir = Path(ssl_dir)
        self.server = server
        self.server_url = server_url
        self.email = email
        self.keylength = keylength
        self.eab_kid = eab_kid
        self.eab_hmac_key = eab_hmac_key

    @property
    def account_dir(self) -> Path:
        """Directory of the account key and registration for the configured CA."""
        return self.data_dir / ACCOUNTS_DIR_NAME / self.server

    def live_dir(self, domain: str) -> Path:
        """Directory holding the private key and issued chain of one certificate."""
        return self.data_dir / LIVE_DIR_NAME / domain

    def cert_paths(self, domain: str) -> dict[str, Path]:
        """Paths the certificate of a domain is published to."""
        return {
            "fullchain": self.ssl_dir / f"{domain}{CERT_SUFFIX_FULLCHAIN}",
            "key": self.ssl_dir / f"{domain}{CERT_SUFFIX_KEY}",
            "cert": self.ssl_dir / f"{domain}{CERT_SUFFIX_CERT}",
            "ca": self.ssl_dir / f"{domain}{CERT_SUFFIX_CA}",
        }

    def certificate_status(self, domains: list[str], renewal_days: int) -> dict[str, Any]:
        """Read the installed certificate and classify it against the renewal threshold."""
        main = domains[0]
        paths = self.cert_paths(main)
        status: dict[str, Any] = {
            "domain": main,
            "domains": domains,
            "status": STATUS_NOT_FOUND,
            "days_remaining": None,
            "expiry_date": None,
            "issuer": None,
            "serial_number": None,
            "certificate_path": str(paths["fullchain"]),
            "key_path": str(paths["key"]),
            "error": None,
        }
        if not paths["fullchain"].is_file():
            return status
        try:
            status.update(certificate_info(paths["fullchain"]))
        except (OSError, ValueError, AcmeError) as err:
            status["status"] = STATUS_ERROR
            status["error"] = str(err)
            return status
        days = status["days_remaining"]
        if days < 0:
            status["status"] = STATUS_EXPIRED
        elif days <= renewal_days:
            status["status"] = STATUS_RENEWAL_REQUIRED
        else:
            status["status"] = STATUS_VALID
        return status

    def issue(
        self,
        domains: list[str],
        *,
        dns_provider: str,
        credentials: dict[str, str],
        propagation_timeout: int = DEFAULT_PROPAGATION_TIMEOUT,
        propagation_interval: int = DEFAULT_PROPAGATION_INTERVAL,
        force: bool = False,
    ) -> IssueResult:
        """Run a full dns-01 issuance and publish the certificate. Blocking, run in an executor."""
        from acme import client as acme_client
        from acme import errors as acme_errors
        from acme import messages

        import josepy as jose

        main = domains[0]
        live = self.live_dir(main)
        live.mkdir(parents=True, exist_ok=True)
        key_path = live / "privkey.pem"
        if force or not key_path.is_file():
            write_private_key(key_path, generate_private_key(self.keylength))
        certificate_key = load_private_key(key_path)

        account_key_path = self.account_dir / "account_key.pem"
        registration_path = self.account_dir / "registration.json"
        if account_key_path.is_file():
            account_key = load_private_key(account_key_path)
        else:
            account_key = rsa.generate_private_key(
                public_exponent=65537, key_size=ACCOUNT_KEY_SIZE
            )
            write_private_key(account_key_path, account_key)
        account_jwk = jose.JWKRSA(key=account_key)

        try:
            net = acme_client.ClientNetwork(
                account_jwk, user_agent=USER_AGENT, timeout=NETWORK_TIMEOUT
            )
            directory = acme_client.ClientV2.get_directory(self.server_url, net)
            client = acme_client.ClientV2(directory, net)

            registration = self._load_registration(registration_path, messages)
            if registration is not None:
                net.account = registration
                try:
                    registration = client.query_registration(registration)
                except acme_errors.Error as err:
                    _LOGGER.info("Stored ACME account was rejected (%s), registering again", err)
                    registration = None
            if registration is None:
                registration = client.new_account(
                    self._registration_body(messages, directory, account_jwk)
                )
                net.account = registration
                _write(registration_path, json.dumps(registration.to_json()), 0o600)

            order = client.new_order(build_csr(certificate_key, domains))
            with DnsChallenge(dns_provider, credentials) as dns:
                published = self._publish_challenges(order, messages, dns, account_jwk)
                deadline = datetime.datetime.now() + datetime.timedelta(seconds=ORDER_TIMEOUT)
                for _, zone, name, value in published:
                    if not wait_for_txt(
                        name, {value}, zone, propagation_timeout, propagation_interval
                    ):
                        raise DnsError(
                            f"TXT record {name} was not published within {propagation_timeout} seconds"
                        )
                for challenge_body, _, _, _ in published:
                    client.answer_challenge(
                        challenge_body, challenge_body.chall.response(account_jwk)
                    )
                order = client.poll_authorizations(order, deadline)
                order = client.finalize_order(order, deadline)
        except (acme_errors.Error, messages.Error) as err:
            raise AcmeError(describe_error(err)) from err

        fullchain = order.fullchain_pem
        cert_pem, chain_pem = split_fullchain(fullchain)
        _write(live / "fullchain.pem", fullchain, 0o644)
        _write(live / "cert.pem", cert_pem, 0o644)
        _write(live / "chain.pem", chain_pem, 0o644)

        paths = self.cert_paths(main)
        _write(paths["fullchain"], fullchain, 0o644)
        _write(paths["cert"], cert_pem, 0o644)
        _write(paths["ca"], chain_pem, 0o644)
        _write(paths["key"], key_path.read_text(encoding="utf-8"), 0o600)

        info = certificate_info(paths["fullchain"])
        _LOGGER.info(
            "Issued certificate for %s, expires %s", ", ".join(domains), info["expiry_date"]
        )
        return IssueResult(
            domains=list(domains),
            cert_path=paths["fullchain"],
            key_path=paths["key"],
            expiry_date=info["expiry_date"],
            days_remaining=info["days_remaining"],
            issuer=info["issuer"],
        )

    def _publish_challenges(
        self, order: Any, messages: Any, dns: DnsChallenge, account_jwk: Any
    ) -> list[tuple[Any, str, str, str]]:
        challenges = []
        for authz in order.authorizations:
            if authz.body.status == messages.STATUS_VALID:
                continue
            challenge_body = next(
                (
                    candidate
                    for candidate in authz.body.challenges
                    if candidate.chall.typ == DNS01_CHALLENGE
                ),
                None,
            )
            if challenge_body is None:
                raise AcmeError(
                    f"{authz.body.identifier.value}: the CA offered no dns-01 challenge"
                )
            zone = authz.body.identifier.value
            name = challenge_body.chall.validation_domain_name(zone)
            value = challenge_body.chall.validation(account_jwk)
            dns.create_txt(zone, name, value)
            challenges.append((challenge_body, zone, name, value))
        return challenges

    def _load_registration(self, path: Path, messages: Any) -> Any:
        if not path.is_file():
            return None
        try:
            return messages.RegistrationResource.from_json(
                json.loads(path.read_text(encoding="utf-8"))
            )
        except (ValueError, KeyError, TypeError) as err:
            _LOGGER.warning("Ignoring unreadable ACME registration %s: %s", path, err)
            return None

    def _registration_body(self, messages: Any, directory: Any, account_jwk: Any) -> Any:
        details: dict[str, Any] = {"terms_of_service_agreed": True}
        if self.email:
            details["email"] = self.email
        if self.eab_kid and self.eab_hmac_key:
            details["external_account_binding"] = messages.ExternalAccountBinding.from_data(
                account_public_key=account_jwk,
                kid=self.eab_kid,
                hmac_key=self.eab_hmac_key,
                directory=directory,
            )
        return messages.NewRegistration.from_data(**details)
