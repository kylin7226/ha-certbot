import datetime as dt
import importlib
from pathlib import Path
import sys
import threading
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1] / "custom_components" / "ha_certbot"
package = ModuleType("cert_test_component")
package.__path__ = [str(ROOT)]
sys.modules[package.__name__] = package
acme = importlib.import_module("cert_test_component.acme")
dns = importlib.import_module("cert_test_component.dns")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Live network access is not allowed in unit tests")
    monkeypatch.setattr("socket.socket.connect", denied)
    monkeypatch.setattr("socket.socket.connect_ex", denied)
    monkeypatch.setattr("socket.socket.sendto", denied)


@pytest.fixture
def manager(tmp_path):
    return acme.CertificateManager(
        data_dir=tmp_path / "data", ssl_dir=tmp_path / "ssl", entry_id="entry-one",
        server="letsencrypt", server_url="https://acme-v02.api.letsencrypt.org/directory",
    )


def certificate(key, domains=("example.com",), days=90, public_key=None, starts=-2):
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    return (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(public_key or key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now + dt.timedelta(days=starts))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in domains]), False)
        .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
    )


def install(manager, domains=("example.com",), days=90):
    key = acme.generate_private_key("ec-256")
    manager._publish_certificate(list(domains), certificate(key, domains, days), key, threading.Event())
    return manager.cert_paths(domains[0])


@pytest.fixture
def client(monkeypatch):
    from acme import messages

    client = Mock()
    registration = messages.RegistrationResource(
        body=messages.Registration(status="valid"), uri="https://ca.invalid/acct/1",
    )
    client.new_account.return_value = registration
    client.query_registration.return_value = registration
    ca_key = acme.generate_private_key("ec-256")

    def new_order(pem):
        csr = x509.load_pem_x509_csr(pem)
        domains = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        return SimpleNamespace(authorizations=[], fullchain_pem=certificate(ca_key, domains, public_key=csr.public_key()))

    client.new_order.side_effect = new_order
    client.poll_authorizations.side_effect = lambda order, deadline: order
    client.finalize_order.side_effect = lambda order, deadline: order
    monkeypatch.setattr("acme.client.ClientV2", Mock(return_value=client))
    return client
