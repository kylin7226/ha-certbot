"""Certificate issuance over ACME (RFC 8555), using certbot's acme library."""
from __future__ import annotations

import datetime
import json
import logging
import os
import re
import shutil
import tempfile
import threading
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from .const import (
    ACCOUNTS_DIR_NAME,
    DATA_DIR_NAME,
    DEFAULT_KEYLENGTH,
    DEFAULT_PROPAGATION_INTERVAL,
    DEFAULT_PROPAGATION_TIMEOUT,
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
from .errors import redact

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


def normalize_server_url(value: str) -> str:
    parts = urlsplit(value.strip())
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.fragment
            or any(char.isspace() for char in value) or "\\" in value):
        raise ValueError("ACME directory must be an HTTPS URL without credentials or a fragment")
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    netloc = f"{host}:{port}" if port is not None and port != 443 else host
    return urlunsplit(("https", netloc, parts.path or "/", parts.query, ""))


def entry_unique_id(server_url: str, domain: str) -> str:
    return f"{sha256(server_url.encode('utf-8')).hexdigest()[:16]}|{domain}"


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
    _write(
        path,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii"),
        0o600,
    )


def load_private_key(path: Path) -> Any:
    """Read back a private key written by write_private_key."""
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def build_csr(key: Any, domains: list[str]) -> bytes:
    """Build a CSR carrying every domain in the subject alternative name extension."""
    subject = []
    if len(domains[0].encode("utf-8")) <= 64:
        subject.append(x509.NameAttribute(NameOID.COMMON_NAME, domains[0]))
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(subject))
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


def certificate_info(pem_path: Path, key_path: Path, domains: list[str]) -> dict[str, Any]:
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
    key = load_private_key(key_path)
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    if certificate.public_key().public_bytes(
        serialization.Encoding.DER, public_format
    ) != key.public_key().public_bytes(serialization.Encoding.DER, public_format):
        raise AcmeError("certificate and private key do not match")
    if not set(domains).issubset({str(name).lower() for name in names}):
        raise AcmeError("certificate does not cover all configured domains")
    now = datetime.datetime.now(datetime.timezone.utc)
    if certificate.not_valid_before_utc > now:
        raise AcmeError("certificate is not yet valid")
    not_after = certificate.not_valid_after_utc
    remaining = not_after - now
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
    return str(exc) or type(exc).__name__


def _write(path: Path, content: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _check_cancelled(cancel_event: threading.Event) -> None:
    if cancel_event.is_set():
        raise AcmeError("certificate operation was cancelled")


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
        entry_id: str,
        server: str,
        server_url: str,
        email: str = "",
        keylength: str = DEFAULT_KEYLENGTH,
        eab_kid: str = "",
        eab_hmac_key: str = "",
    ) -> None:
        self.data_dir = Path(data_dir)
        self.ssl_dir = Path(ssl_dir)
        self.entry_id = entry_id
        self.server = server
        self.server_url = server_url
        self.server_id = sha256(server_url.encode("utf-8")).hexdigest()[:16]
        self.email = email
        self.keylength = keylength
        self.eab_kid = eab_kid
        self.eab_hmac_key = eab_hmac_key

    @property
    def account_dir(self) -> Path:
        """Directory of the account key and registration for the configured CA."""
        return self.data_dir / ACCOUNTS_DIR_NAME / self.server_id / self.entry_id

    def live_dir(self, domain: str) -> Path:
        return self.ssl_dir / DATA_DIR_NAME / self.entry_id / self.server_id / domain

    def cert_paths(self, domain: str) -> dict[str, Path]:
        current = self.live_dir(domain) / "current"
        return {
            "fullchain": current / "fullchain.pem",
            "key": current / "privkey.pem",
            "cert": current / "cert.pem",
            "ca": current / "chain.pem",
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
            current = paths["fullchain"].parent.resolve(strict=True)
            status.update(certificate_info(current / "fullchain.pem", current / "privkey.pem", domains))
        except (OSError, ValueError, TypeError, AcmeError) as err:
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
        cancel_event: threading.Event | None = None,
    ) -> IssueResult:
        """Run a full dns-01 issuance and publish the certificate. Blocking, run in an executor."""
        from acme import client as acme_client
        from acme import errors as acme_errors
        from acme import messages

        import josepy as jose

        cancel_event = cancel_event or threading.Event()
        _check_cancelled(cancel_event)
        main = domains[0]
        key_path = self.cert_paths(main)["key"]
        certificate_key = None
        if not force and key_path.is_file():
            try:
                certificate_key = load_private_key(key_path)
            except (ValueError, TypeError):
                pass
        if certificate_key is None:
            certificate_key = generate_private_key(self.keylength)

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
                try:
                    registration = client.query_registration(registration)
                except messages.Error as err:
                    if err.code != "accountDoesNotExist":
                        raise
                    net.account = None
                    registration = None
            if registration is None:
                try:
                    registration = client.new_account(
                        self._registration_body(messages, directory, account_jwk)
                    )
                except acme_errors.ConflictError as err:
                    registration = client.query_registration(
                        messages.RegistrationResource(
                            body=messages.Registration(), uri=err.location
                        )
                    )
            if registration.body.status != "valid":
                raise AcmeError("the ACME account is not valid; contact the CA before retrying")
            net.account = registration
            _write(registration_path, json.dumps(registration.to_json()), 0o600)

            _check_cancelled(cancel_event)
            order = client.new_order(build_csr(certificate_key, domains))
            with DnsChallenge(dns_provider, credentials) as dns:
                published = self._publish_challenges(order, messages, dns, account_jwk, cancel_event)
                for _, zone, name, value in published:
                    _check_cancelled(cancel_event)
                    propagated = wait_for_txt(
                        name, {value}, zone, propagation_timeout, propagation_interval,
                        cancel_event=cancel_event,
                    )
                    _check_cancelled(cancel_event)
                    if not propagated:
                        raise DnsError(
                            f"TXT record {name} was not published within {propagation_timeout} seconds"
                        )
                for challenge_body, _, _, _ in published:
                    _check_cancelled(cancel_event)
                    client.answer_challenge(
                        challenge_body, challenge_body.chall.response(account_jwk)
                    )
                _check_cancelled(cancel_event)
                deadline = datetime.datetime.now() + datetime.timedelta(seconds=ORDER_TIMEOUT)
                order = client.poll_authorizations(order, deadline)
                _check_cancelled(cancel_event)
                deadline = datetime.datetime.now() + datetime.timedelta(seconds=ORDER_TIMEOUT)
                order = client.finalize_order(order, deadline)
        except (acme_errors.Error, messages.Error, jose.errors.Error) as err:
            raise AcmeError(redact(
                describe_error(err), (*credentials.values(), self.eab_kid, self.eab_hmac_key)
            )) from None

        _check_cancelled(cancel_event)
        info = self._publish_certificate(domains, order.fullchain_pem, certificate_key, cancel_event)
        paths = self.cert_paths(main)
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

    def _publish_certificate(
        self, domains: list[str], fullchain: str, key: Any, cancel_event: threading.Event
    ) -> dict[str, Any]:
        cert_pem, chain_pem = split_fullchain(fullchain)
        live = self.live_dir(domains[0])
        live.mkdir(parents=True, exist_ok=True)
        generation = Path(tempfile.mkdtemp(prefix="generation-", dir=live))
        pending = live / f".current-{uuid4().hex}"
        published = False
        try:
            _write(generation / "fullchain.pem", fullchain, 0o644)
            _write(generation / "cert.pem", cert_pem, 0o644)
            _write(generation / "chain.pem", chain_pem, 0o644)
            write_private_key(generation / "privkey.pem", key)
            info = certificate_info(generation / "fullchain.pem", generation / "privkey.pem", domains)
            if info["days_remaining"] < 0:
                raise AcmeError("the CA returned an expired certificate")
            _check_cancelled(cancel_event)
            pending.symlink_to(generation.name, target_is_directory=True)
            os.replace(pending, live / "current")
            published = True
            return info
        finally:
            pending.unlink(missing_ok=True)
            if not published:
                shutil.rmtree(generation)

    def _publish_challenges(
        self, order: Any, messages: Any, dns: DnsChallenge, account_jwk: Any,
        cancel_event: threading.Event,
    ) -> list[tuple[Any, str, str, str]]:
        challenges = []
        for authz in order.authorizations:
            _check_cancelled(cancel_event)
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
        from josepy.errors import DeserializationError

        if not path.is_file():
            return None
        try:
            return messages.RegistrationResource.from_json(
                json.loads(path.read_text(encoding="utf-8"))
            )
        except (ValueError, KeyError, TypeError, DeserializationError) as err:
            _LOGGER.warning("Ignoring unreadable ACME registration (%s)", type(err).__name__)
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
