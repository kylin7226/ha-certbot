import datetime as dt
from pathlib import Path
import stat
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from cryptography import x509

from conftest import ROOT, acme, certificate, install


@pytest.mark.parametrize("keylength", ["2048", "3072", "4096", "ec-256", "ec-384"])
def test_csr_key_types(keylength):
    key = acme.generate_private_key(keylength)
    csr = x509.load_pem_x509_csr(acme.build_csr(key, ["example.com", "*.example.com"]))
    assert csr.is_signature_valid
    assert csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == ["example.com", "*.example.com"]


@pytest.mark.parametrize("invalid", ["../example.com", "/etc/passwd", "a;b.com", "localhost", "*.*.example.com"])
def test_reject_unsafe_domains(invalid):
    with pytest.raises(ValueError):
        acme.parse_domains(invalid)


def test_issuance_and_key_reuse(manager, client):
    result = manager.issue(["example.com", "*.example.com"], dns_provider="aliyun", credentials={})
    before = result.key_path.read_bytes()
    assert manager.certificate_status(["example.com", "*.example.com"], 30)["status"] == "valid"
    assert stat.S_IMODE(result.key_path.stat().st_mode) == 0o600
    assert (manager.account_dir / "registration.json").is_file()
    manager.issue(["example.com", "*.example.com"], dns_provider="aliyun", credentials={})
    assert result.key_path.read_bytes() == before
    manager.issue(["example.com", "*.example.com"], dns_provider="aliyun", credentials={}, force=True)
    assert result.key_path.read_bytes() != before


@pytest.mark.parametrize("fault", ["missing_key", "wrong_key", "corrupt_key", "missing_san", "corrupt_cert"])
def test_invalid_installed_certificate(manager, fault):
    paths = install(manager)
    domains = ["example.com"]
    if fault == "missing_key":
        paths["key"].unlink()
    elif fault == "wrong_key":
        acme.write_private_key(paths["key"], acme.generate_private_key("ec-256"))
    elif fault == "corrupt_key":
        paths["key"].write_text("not a key")
    elif fault == "missing_san":
        domains.append("*.example.com")
    else:
        paths["fullchain"].write_text("not a certificate")
    assert manager.certificate_status(domains, 30)["status"] == "error"


def test_expiry_states(manager):
    assert manager.certificate_status(["example.com"], 30)["status"] == "not_found"
    paths = install(manager, days=10)
    assert manager.certificate_status(["example.com"], 30)["status"] == "renewal_required"
    key = acme.load_private_key(paths["key"])
    paths["fullchain"].write_text(certificate(key, days=-1))
    assert manager.certificate_status(["example.com"], 30)["status"] == "expired"


@pytest.mark.parametrize("fault", ["missing", "corrupt", "mismatch"])
def test_reissue_repairs_private_key(manager, client, fault):
    paths = install(manager)
    if fault == "missing":
        paths["key"].unlink()
    elif fault == "corrupt":
        paths["key"].write_text("invalid key")
    else:
        acme.write_private_key(paths["key"], acme.generate_private_key("ec-256"))
    manager.issue(["example.com"], dns_provider="aliyun", credentials={})
    assert manager.certificate_status(["example.com"], 30)["status"] == "valid"


@pytest.mark.parametrize("entry_id,url", [
    ("entry-two", "https://acme-v02.api.letsencrypt.org/directory"),
    ("entry-one", "https://acme-staging-v02.api.letsencrypt.org/directory"),
    ("entry-one", "https://other-ca.invalid/directory"),
])
def test_ca_and_entry_isolation(manager, entry_id, url):
    other = acme.CertificateManager(data_dir=manager.data_dir, ssl_dir=manager.ssl_dir,
        entry_id=entry_id, server="custom", server_url=url)
    assert other.account_dir != manager.account_dir
    assert other.cert_paths("example.com") != manager.cert_paths("example.com")
    assert other.live_dir("example.com") != manager.live_dir("example.com")


@pytest.mark.parametrize("failure", ["fullchain.pem", "cert.pem", "chain.pem", "privkey.pem", "switch"])
def test_failed_publish_preserves_entire_old_generation(manager, monkeypatch, failure):
    paths = install(manager)
    before = {name: path.read_bytes() for name, path in paths.items()}
    previous = paths["fullchain"].parent.resolve()
    write = acme._write
    replace = acme.os.replace

    def fail_write(path, content, mode):
        if path.name == failure:
            raise OSError("simulated disk failure")
        write(path, content, mode)

    def fail_replace(source, target):
        if failure == "switch" and Path(target).name == "current":
            raise OSError("simulated disk failure")
        replace(source, target)

    monkeypatch.setattr(acme, "_write", fail_write)
    monkeypatch.setattr(acme.os, "replace", fail_replace)
    key = acme.generate_private_key("ec-256")
    with pytest.raises(OSError, match="simulated disk failure"):
        manager._publish_certificate(["example.com"], certificate(key), key, threading.Event())
    assert {name: path.read_bytes() for name, path in paths.items()} == before
    assert paths["fullchain"].parent.resolve() == previous
    assert list(manager.live_dir("example.com").glob("generation-*")) == [previous]


def test_current_switches_only_after_validation(manager, monkeypatch):
    paths = install(manager)
    before = paths["fullchain"].read_bytes()
    key = acme.generate_private_key("ec-256")
    replace = acme.os.replace
    switches = []

    def inspect_replace(source, target):
        if Path(target).name == "current":
            assert paths["fullchain"].read_bytes() == before
            pending = Path(source).resolve()
            assert acme.certificate_info(pending / "fullchain.pem", pending / "privkey.pem", ["example.com"])["days_remaining"] > 0
            switches.append(source)
        replace(source, target)

    monkeypatch.setattr(acme.os, "replace", inspect_replace)
    manager._publish_certificate(["example.com"], certificate(key), key, threading.Event())
    assert len(switches) == 1
    assert paths["fullchain"].read_bytes() != before
    assert manager.certificate_status(["example.com"], 30)["status"] == "valid"


@pytest.mark.parametrize("fault", ["wrong_key", "wrong_domain", "not_yet_valid", "expired"])
def test_reject_bad_ca_response_without_publishing(manager, fault):
    paths = install(manager)
    before = paths["fullchain"].read_bytes()
    key = acme.generate_private_key("ec-256")
    pem = certificate(key)
    if fault == "wrong_key":
        pem = certificate(acme.generate_private_key("ec-256"))
    elif fault == "wrong_domain":
        pem = certificate(key, ["wrong.example.com"])
    elif fault == "not_yet_valid":
        pem = certificate(key, starts=1)
    else:
        pem = certificate(key, days=-1)
    with pytest.raises(acme.AcmeError):
        manager._publish_certificate(["example.com"], pem, key, threading.Event())
    assert paths["fullchain"].read_bytes() == before


def test_private_key_private_before_replace(tmp_path, monkeypatch):
    path = tmp_path / "key.pem"
    replace = acme.os.replace
    modes = []

    def inspect_replace(source, target):
        if Path(target) == path:
            modes.append(stat.S_IMODE(Path(source).stat().st_mode))
        replace(source, target)

    monkeypatch.setattr(acme.os, "replace", inspect_replace)
    previous = acme.os.umask(0o022)
    try:
        acme.write_private_key(path, acme.generate_private_key("ec-256"))
    finally:
        acme.os.umask(previous)
    assert modes == [0o600]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_failed_order_does_not_rotate_live_key(manager, client):
    paths = install(manager)
    before = {name: path.read_bytes() for name, path in paths.items()}
    client.new_order.side_effect = RuntimeError("CA unavailable")
    with pytest.raises(RuntimeError):
        manager.issue(["example.com"], dns_provider="aliyun", credentials={}, force=True)
    assert {name: path.read_bytes() for name, path in paths.items()} == before


def test_dns_and_polling_have_independent_deadlines(manager, client, monkeypatch):
    clock = {"now": dt.datetime.now()}

    class Clock(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return clock["now"] if tz is None else clock["now"].astimezone(tz)

    def wait(*args, **kwargs):
        clock["now"] += dt.timedelta(seconds=200)
        return True

    def poll(order, deadline):
        assert deadline > clock["now"]
        clock["now"] += dt.timedelta(seconds=170)
        return order

    def finalize(order, deadline):
        assert deadline > clock["now"]
        return order

    monkeypatch.setattr(acme, "datetime", SimpleNamespace(datetime=Clock, timedelta=dt.timedelta, timezone=dt.timezone))
    monkeypatch.setattr(acme, "wait_for_txt", wait)
    monkeypatch.setattr(manager, "_publish_challenges", Mock(return_value=[(Mock(), "example.com", "_acme-challenge.example.com", "token")]))
    client.poll_authorizations.side_effect = poll
    client.finalize_order.side_effect = finalize
    manager.issue(["example.com"], dns_provider="aliyun", credentials={}, propagation_timeout=300)


def test_integration_naming_and_metadata():
    import ast
    import importlib
    import json

    import yaml

    const = importlib.import_module(f"{acme.__package__}.const")
    manifest = json.loads((ROOT / "manifest.json").read_text())
    hacs = json.loads((ROOT.parents[1] / "hacs.json").read_text())
    services = yaml.safe_load((ROOT / "services.yaml").read_text())
    assert ROOT.name == const.DOMAIN == const.DATA_DIR_NAME == manifest["domain"] == "ha_certbot"
    assert manifest["name"] == hacs["name"] == "ha-certbot"
    assert services["issue_certificate"]["fields"]["config_entry_id"]["selector"]["config_entry"]["integration"] == const.DOMAIN
    assert const.EVENT_ISSUED == "ha_certbot_issued"
    assert const.EVENT_FAILED == "ha_certbot_failed"
    assert const.USER_AGENT.startswith("ha-certbot/")
    for path in ROOT.rglob("*.json"):
        json.loads(path.read_text())
    for path in ROOT.rglob("*.py"):
        ast.parse(path.read_text())
    for path in [ROOT / "strings.json", ROOT / "translations" / "zh-Hans.json"]:
        text = json.loads(path.read_text())
        assert text["config"]["step"]["user"]["title"] == "ha-certbot"
        assert text["options"]["step"]["init"]["title"].startswith("ha-certbot")


def test_cancel_after_ca_poll_does_not_publish(manager, client):
    paths = install(manager)
    before = paths["fullchain"].read_bytes()
    cancel = threading.Event()

    def poll(order, deadline):
        cancel.set()
        return order

    client.poll_authorizations.side_effect = poll
    with pytest.raises(acme.AcmeError, match="cancelled"):
        manager.issue(["example.com"], dns_provider="aliyun", credentials={}, cancel_event=cancel)
    client.finalize_order.assert_not_called()
    assert paths["fullchain"].read_bytes() == before


@pytest.mark.parametrize("contents", [None, "{", "{}", '{"uri": "secret-marker"}'])
def test_existing_account_registration_recovery(manager, client, contents, caplog):
    from acme import errors, messages

    path = manager.account_dir / "registration.json"
    acme.write_private_key(manager.account_dir / "account_key.pem", acme.generate_private_key("2048"))
    key_before = (manager.account_dir / "account_key.pem").read_bytes()
    if contents is not None:
        path.write_text(contents)
    client.new_account.side_effect = errors.ConflictError("https://ca.invalid/acct/1")
    manager.issue(["example.com"], dns_provider="aliyun", credentials={})
    client.query_registration.assert_called_once()
    restored = manager._load_registration(path, messages)
    assert restored.body.status == "valid"
    assert (manager.account_dir / "account_key.pem").read_bytes() == key_before
    assert "secret-marker" not in caplog.text


def test_account_query_network_failure_does_not_register_again(manager, client):
    from acme import errors

    manager.issue(["example.com"], dns_provider="aliyun", credentials={})
    client.new_account.reset_mock()
    client.query_registration.side_effect = errors.ClientError("network unavailable")
    with pytest.raises(acme.AcmeError, match="network unavailable"):
        manager.issue(["example.com"], dns_provider="aliyun", credentials={})
    client.new_account.assert_not_called()


def test_missing_remote_account_can_register_again(manager, client):
    from acme import messages

    manager.issue(["example.com"], dns_provider="aliyun", credentials={})
    client.new_account.reset_mock()
    client.query_registration.side_effect = messages.Error(typ="urn:ietf:params:acme:error:accountDoesNotExist")
    manager.issue(["example.com"], dns_provider="aliyun", credentials={})
    client.new_account.assert_called_once()


def test_inactive_account_does_not_issue(manager, client):
    from acme import messages

    client.new_account.return_value = messages.RegistrationResource(
        body=messages.Registration(status="deactivated"), uri="https://ca.invalid/acct/1"
    )
    with pytest.raises(acme.AcmeError, match="account is not valid"):
        manager.issue(["example.com"], dns_provider="aliyun", credentials={})
    client.new_order.assert_not_called()


def test_long_domain_uses_san_without_invalid_common_name():
    from cryptography.x509.oid import NameOID

    domains = acme.parse_domains("a" * 63 + ".example.com")
    csr = x509.load_pem_x509_csr(acme.build_csr(acme.generate_private_key("ec-256"), domains))
    assert csr.is_signature_valid
    assert not csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == domains


def test_release_materials_and_ci_are_consistent():
    import json
    import yaml

    root = ROOT.parents[1]
    manifest = json.loads((ROOT / "manifest.json").read_text())
    hacs = json.loads((root / "hacs.json").read_text())
    requirements = set((root / "requirements-test.txt").read_text().splitlines())
    workflow = yaml.safe_load((root / ".github/workflows/checks.yaml").read_text())
    assert set(manifest["requirements"]) <= requirements
    assert hacs["homeassistant"] == "2026.11.1"
    assert manifest["version"] == "2.0.0"
    assert "MIT License" in (root / "LICENSE").read_text()
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"]["cancel-in-progress"] is True
    assert set(workflow["jobs"]) == {"regression", "homeassistant"}
