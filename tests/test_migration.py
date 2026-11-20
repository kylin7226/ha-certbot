import importlib
import json
import stat
import threading

import pytest
from acme import messages

from conftest import acme, certificate, install

migration = importlib.import_module("cert_test_component.migration")


def test_import_copies_isolated_legacy_data_without_changing_originals(manager):
    old_id = "old-entry"
    source = manager.data_dir.parent / "acme_cert" / "accounts" / manager.server_id / old_id
    acme.write_private_key(source / "account_key.pem", acme.generate_private_key("2048"))
    registration = messages.RegistrationResource(body=messages.Registration(status="valid"), uri="https://ca.invalid/acct/1")
    (source / "registration.json").write_text(json.dumps(registration.to_json()))
    live = manager.ssl_dir / "acme_cert" / old_id / manager.server_id / "example.com" / "current"
    key = acme.generate_private_key("ec-256")
    acme.write_private_key(live / "privkey.pem", key)
    (live / "fullchain.pem").write_text(certificate(key))
    originals = {path: path.read_bytes() for root in (source, live) for path in root.iterdir()}
    migration.import_legacy(manager, old_id, ["example.com"])
    assert all(path.read_bytes() == content for path, content in originals.items())
    assert manager.certificate_status(["example.com"], 30)["status"] == "valid"
    assert (manager.account_dir / "account_key.pem").read_bytes() == originals[source / "account_key.pem"]
    assert stat.S_IMODE((manager.account_dir / "account_key.pem").stat().st_mode) == 0o600
    current = manager.cert_paths("example.com")["fullchain"].resolve()
    migration.import_legacy(manager, old_id, ["example.com"])
    assert manager.cert_paths("example.com")["fullchain"].resolve() == current


def test_legacy_shared_certificate_is_not_assumed_to_belong_to_ca(manager):
    manager.ssl_dir.mkdir(parents=True)
    shared = manager.ssl_dir / "example.com.pem"
    shared.write_text("unattributed old certificate")
    migration.import_legacy(manager, "old-entry", ["example.com"])
    assert shared.read_text() == "unattributed old certificate"
    assert manager.certificate_status(["example.com"], 30)["status"] == "not_found"


def test_legacy_builtin_account_can_be_copied(manager):
    source = manager.data_dir.parent / "acme_cert" / "accounts" / manager.server / "account_key.pem"
    acme.write_private_key(source, acme.generate_private_key("2048"))
    migration.import_legacy(manager, "old-entry", ["example.com"])
    assert (manager.account_dir / "account_key.pem").read_bytes() == source.read_bytes()


def test_legacy_custom_account_without_endpoint_is_not_copied(manager):
    manager.server = "custom"
    source = manager.data_dir.parent / "acme_cert" / "accounts" / "custom" / "account_key.pem"
    acme.write_private_key(source, acme.generate_private_key("2048"))
    migration.import_legacy(manager, "old-entry", ["example.com"])
    assert source.is_file()
    assert not (manager.account_dir / "account_key.pem").exists()


def test_existing_new_account_and_certificate_are_not_overwritten(manager):
    paths = install(manager)
    acme.write_private_key(manager.account_dir / "account_key.pem", acme.generate_private_key("2048"))
    before = {path: path.read_bytes() for path in (*paths.values(), manager.account_dir / "account_key.pem")}
    source = manager.data_dir.parent / "acme_cert" / "accounts" / manager.server / "account_key.pem"
    acme.write_private_key(source, acme.generate_private_key("2048"))
    migration.import_legacy(manager, "old-entry", ["example.com"])
    assert all(path.read_bytes() == content for path, content in before.items())
