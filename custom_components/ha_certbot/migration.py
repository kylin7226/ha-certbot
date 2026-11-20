from __future__ import annotations

import json
import logging
import threading

from .acme import CertificateManager, certificate_info, load_private_key, write_private_key, _write
from .const import ACME_SERVERS, LEGACY_DOMAIN

_LOGGER = logging.getLogger(__name__)


def import_legacy(manager: CertificateManager, entry_id: str, domains: list[str]) -> None:
    from acme import messages

    legacy_data = manager.data_dir.parent / LEGACY_DOMAIN
    accounts = [legacy_data / "accounts" / manager.server_id / entry_id]
    if ACME_SERVERS.get(manager.server) == manager.server_url:
        accounts.append(legacy_data / "accounts" / manager.server)
    if not (manager.account_dir / "account_key.pem").exists():
        for source in accounts:
            if not (source / "account_key.pem").is_file():
                continue
            key = load_private_key(source / "account_key.pem")
            registration = manager._load_registration(source / "registration.json", messages)
            write_private_key(manager.account_dir / "account_key.pem", key)
            if registration is not None:
                _write(manager.account_dir / "registration.json", json.dumps(registration.to_json()), 0o600)
            break

    if manager.cert_paths(domains[0])["fullchain"].exists():
        return
    source = manager.ssl_dir / LEGACY_DOMAIN / entry_id / manager.server_id / domains[0] / "current"
    if not source.is_dir():
        _LOGGER.info("Legacy shared certificates are retained; a CA-isolated certificate will be issued")
        return
    source = source.resolve(strict=True)
    info = certificate_info(source / "fullchain.pem", source / "privkey.pem", domains)
    if info["days_remaining"] < 0:
        return
    manager._publish_certificate(
        domains, (source / "fullchain.pem").read_text(encoding="utf-8"),
        load_private_key(source / "privkey.pem"), threading.Event(),
    )
