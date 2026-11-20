import base64
import hashlib
import hmac
import json
import re
import threading
from types import SimpleNamespace
from urllib.parse import quote
from unittest.mock import Mock

from dns.name import from_text as dns_name
import pytest
import requests
from lexicon._private.discovery import load_provider_module
from lexicon.config import ConfigResolver

from conftest import acme, dns


def provider(name):
    cls = dns._bounded_provider(name, load_provider_module(name).Provider)
    return cls(ConfigResolver().with_dict({
        "provider_name": name, "domain": "example.com",
        name: {"auth_key_id": "TEST_ID", "auth_secret": "TEST_SECRET", "auth_token": "TEST_TOKEN"},
    }))


def response(data, status=200):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(data).encode()
    result.url = "https://api.invalid/?token=TEST_SECRET"
    return result


def test_aliyun_timestamp_and_fields():
    assert {"auth_key_id", "auth_secret"} <= {name for name, _ in dns.provider_options("aliyun")}
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", provider("aliyun")._build_signature_parameters()["Timestamp"])


@pytest.mark.parametrize("name", ["aliyun", "cloudflare"])
def test_bounded_requests(monkeypatch, name):
    request = Mock(return_value=response({}))
    monkeypatch.setattr(requests, "request", request)
    provider(name)._request()
    assert request.call_args.kwargs["timeout"] == dns.NETWORK_TIMEOUT


@pytest.fixture
def aliyun_api(monkeypatch):
    records = []
    actions = []
    nonces = set()

    def request(method, url, *, params, timeout):
        assert method == "GET"
        assert url == "https://alidns.aliyuncs.com"
        assert timeout == dns.NETWORK_TIMEOUT
        assert params["AccessKeyId"] == "TEST_ID"
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", params["Timestamp"])
        assert params["SignatureNonce"] not in nonces
        nonces.add(params["SignatureNonce"])
        canonical = "&".join(f"{quote(str(k), safe='-_.~')}={quote(str(v), safe='-_.~')}" for k, v in sorted(params.items()) if k != "Signature")
        signed = "GET&%2F&" + quote(canonical, safe="-_.~")
        expected = base64.b64encode(hmac.new(b"TEST_SECRET&", signed.encode(), hashlib.sha1).digest()).decode()
        assert params["Signature"] == expected
        assert params["DomainName"] == "example.com"
        action = params["Action"]
        actions.append(action)
        if action == "DescribeDomainInfo":
            data = {"DomainId": "zone-id"}
        elif action == "DescribeDomainRecords":
            found = [r for r in records if r["Type"] == params.get("TypeKeyWord", r["Type"]) and r["RR"] == params.get("RRKeyWord", r["RR"]) and r["Value"] == params.get("ValueKeyWord", r["Value"])]
            data = {"DomainRecords": {"Record": found}}
        elif action == "AddDomainRecord":
            assert params["RR"] == "_acme-challenge"
            assert params["Type"] == "TXT"
            assert params["TTL"] > 0
            record = {"RecordId": f"record-{len(records)}", "Type": "TXT", "RR": params["RR"], "Value": params["Value"], "TTL": params["TTL"]}
            records.append(record)
            data = {"RecordId": record["RecordId"]}
        elif action == "DeleteDomainRecord":
            records[:] = [r for r in records if r["RecordId"] != params["RecordId"]]
            data = {"RecordId": params["RecordId"]}
        else:
            raise AssertionError(action)
        return response(data)

    monkeypatch.setattr(requests, "request", request)
    monkeypatch.setattr("dns.resolver.zone_for_name", lambda *args, **kwargs: dns_name("example.com"))
    return SimpleNamespace(records=records, actions=actions)


def test_aliyun_auth_create_cleanup_and_rfc_signature(aliyun_api):
    records, actions = aliyun_api.records, aliyun_api.actions
    with dns.DnsChallenge("aliyun", {"auth_key_id": "TEST_ID", "auth_secret": "TEST_SECRET"}) as challenge:
        challenge.authenticate("example.com")
        challenge.create_txt("example.com", "_acme-challenge.example.com", "root-token")
        challenge.create_txt("example.com", "_acme-challenge.example.com", "wildcard-token")
        assert {r["Value"] for r in records} == {"root-token", "wildcard-token"}
    assert not records
    assert actions.count("DescribeDomainInfo") == 1
    assert actions.count("AddDomainRecord") == actions.count("DeleteDomainRecord") == 2



@pytest.mark.parametrize("fail_validation", [False, True])
def test_aliyun_acme_root_and_wildcard(manager, client, aliyun_api, monkeypatch, fail_validation):
    from acme import challenges, messages

    original_order = client.new_order.side_effect

    def new_order(csr):
        order = original_order(csr)
        order.authorizations = [
            SimpleNamespace(body=SimpleNamespace(
                status=messages.STATUS_PENDING,
                identifier=SimpleNamespace(value="example.com"),
                challenges=[messages.ChallengeBody(chall=challenges.DNS01(token=token))],
            )) for token in (b"root-challenge-token", b"wildcard-challenge-token")
        ]
        return order

    def propagated(name, values, zone, *args, **kwargs):
        assert name == "_acme-challenge.example.com"
        assert zone == "example.com"
        assert len(aliyun_api.records) == 2
        return values.issubset({record["Value"] for record in aliyun_api.records})

    client.new_order.side_effect = new_order
    monkeypatch.setattr(acme, "wait_for_txt", propagated)
    if fail_validation:
        client.poll_authorizations.side_effect = acme.AcmeError("CA rejected challenge")
        with pytest.raises(acme.AcmeError):
            manager.issue(["example.com", "*.example.com"], dns_provider="aliyun", credentials={"auth_key_id": "TEST_ID", "auth_secret": "TEST_SECRET"})
        assert manager.certificate_status(["example.com", "*.example.com"], 30)["status"] == "not_found"
    else:
        manager.issue(["example.com", "*.example.com"], dns_provider="aliyun", credentials={"auth_key_id": "TEST_ID", "auth_secret": "TEST_SECRET"})
        assert manager.certificate_status(["example.com", "*.example.com"], 30)["status"] == "valid"
    assert client.answer_challenge.call_count == 2
    assert not aliyun_api.records
    assert aliyun_api.actions.count("AddDomainRecord") == aliyun_api.actions.count("DeleteDomainRecord") == 2


@pytest.mark.parametrize("error", [requests.Timeout("TEST_SECRET"), requests.HTTPError(response=response({}, 403))])
def test_aliyun_errors_do_not_expose_query_credentials(monkeypatch, error):
    monkeypatch.setattr(requests, "request", Mock(side_effect=error))
    with pytest.raises(dns.DnsError) as caught:
        provider("aliyun")._request()
    assert "TEST_SECRET" not in str(caught.value)


def test_delegated_zone_preserved(monkeypatch):
    monkeypatch.setattr("dns.resolver.zone_for_name", lambda *args, **kwargs: dns_name("child.example.com"))
    request = Mock(return_value=response({"DomainId": "child-zone"}))
    monkeypatch.setattr(requests, "request", request)
    with dns.DnsChallenge("aliyun", {"auth_key_id": "TEST_ID", "auth_secret": "TEST_SECRET"}) as challenge:
        challenge.authenticate("ha.child.example.com")
    assert request.call_args.kwargs["params"]["DomainName"] == "child.example.com"


def test_authoritative_zone_discovery(monkeypatch):
    monkeypatch.setattr("dns.resolver.zone_for_name", lambda *args, **kwargs: dns_name("example.com"))

    def resolve(name, kind, **kwargs):
        if str(name).rstrip(".") == "example.com" and kind == "NS":
            return [SimpleNamespace(target="ns.example.com")]
        if str(name) == "ns.example.com" and kind == "A":
            return ["192.0.2.1"]
        raise AssertionError((name, kind))

    monkeypatch.setattr("dns.resolver.resolve", resolve)
    assert dns.nameserver_addresses("ha.example.com") == ["192.0.2.1"]


def test_dns_wait_is_interruptible(monkeypatch):
    cancel = threading.Event()
    monkeypatch.setattr(dns, "nameserver_addresses", lambda zone: [])

    def lookup(*args):
        cancel.set()
        return set()

    monkeypatch.setattr(dns, "published_txt_values", lookup)
    assert not dns.wait_for_txt("_acme-challenge.example.com", {"token"}, "example.com", 3600, 300, cancel_event=cancel)


def test_cloudflare_record_exists_response_preserved(monkeypatch):
    monkeypatch.setattr(requests, "request", Mock(return_value=response({"errors": [{"code": 81057}]}, 400)))
    assert provider("cloudflare").create_record("TXT", "_acme-challenge.example.com", "token") is True


def test_preexisting_aliyun_record_is_preserved(aliyun_api):
    record = {"RecordId": "old", "Type": "TXT", "RR": "_acme-challenge", "Value": "token", "TTL": 600}
    aliyun_api.records.append(record)
    with dns.DnsChallenge("aliyun", {"auth_key_id": "TEST_ID", "auth_secret": "TEST_SECRET"}) as challenge:
        challenge.create_txt("example.com", "_acme-challenge.example.com", "token")
    assert aliyun_api.records == [record]
    assert "DeleteDomainRecord" not in aliyun_api.actions
    assert "AddDomainRecord" not in aliyun_api.actions


def test_create_false_is_not_tracked_as_success():
    operations = Mock()
    operations.list_records.return_value = []
    operations.create_record.return_value = False
    with dns.DnsChallenge("cloudflare", {}) as challenge:
        challenge._operations["example.com"] = operations
        with pytest.raises(dns.DnsError, match="refused to create"):
            challenge.create_txt("example.com", "_acme-challenge.example.com", "token")
    operations.delete_record.assert_not_called()


@pytest.mark.parametrize("delete_result", [True, False])
def test_cleanup_uses_record_id_and_checks_result(delete_result, caplog):
    operations = Mock()
    record = {"id": "owned", "type": "TXT", "name": "_acme-challenge.example.com", "content": "token"}
    operations.list_records.side_effect = [[], [record], [record]]
    operations.create_record.return_value = True
    operations.delete_record.return_value = delete_result
    with dns.DnsChallenge("cloudflare", {}) as challenge:
        challenge._operations["example.com"] = operations
        challenge.create_txt("example.com", record["name"], "token")
    operations.delete_record.assert_called_once_with(identifier="owned", rtype="TXT", name=record["name"], content="token")
    assert ("Could not remove" in caplog.text) is (not delete_result)


def test_cleanup_does_not_remove_a_replacement_record():
    operations = Mock()
    record = {"id": "owned", "type": "TXT", "name": "_acme-challenge.example.com", "content": "token"}
    replacement = {**record, "id": "someone-else"}
    operations.list_records.side_effect = [[], [record], [replacement]]
    with dns.DnsChallenge("cloudflare", {}) as challenge:
        challenge._operations["example.com"] = operations
        challenge.create_txt("example.com", record["name"], "token")
    operations.delete_record.assert_not_called()


def test_unidentifiable_record_is_not_blindly_deleted():
    operations = Mock()
    operations.list_records.return_value = []
    with dns.DnsChallenge("cloudflare", {}) as challenge:
        challenge._operations["example.com"] = operations
        with pytest.raises(dns.DnsError, match="Cannot identify"):
            challenge.create_txt("example.com", "_acme-challenge.example.com", "token")
    operations.delete_record.assert_not_called()
