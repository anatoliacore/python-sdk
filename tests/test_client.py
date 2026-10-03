import json
import hashlib
import hmac
from email.message import Message
import pytest

from anatoliacore import AnatoliaCore, verify_webhook


class Response:
    def __init__(self, body, status=200, headers=None):
        self.body = json.dumps(body).encode()
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"
        for name, value in (headers or {}).items():
            self.headers[name] = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _size=None):
        return self.body


class Opener:
    def __init__(self):
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return Response([{"id": "instance-1"}])


def test_client_sets_auth_without_putting_secret_in_url_and_generates_idempotency_key():
    opener = Opener()
    client = AnatoliaCore(api_key="ac_live_" + "x" * 64, opener=opener)
    assert client.create_instance({"name": "one"}) == [{"id": "instance-1"}]
    request, timeout = opener.requests[0]
    assert timeout == 30
    assert "ac_live_" not in request.full_url
    assert request.headers["X-api-key"].startswith("ac_live_")
    assert len(request.headers["Idempotency-key"]) >= 16


def test_client_exposes_operation_metadata_for_polling():
    class OperationOpener(Opener):
        def open(self, request, timeout):
            self.requests.append((request, timeout))
            return Response(
                {"id": "instance-1"},
                headers={
                    "X-Operation-ID": "operation-1",
                    "Operation-Location": "/api/public/v1/operations/operation-1",
                },
            )

    client = AnatoliaCore(api_key="ac_live_" + "x" * 64, opener=OperationOpener())
    result = client.request_with_metadata("POST", "/instances", body={"name": "one"})
    assert result.operation_id == "operation-1"
    assert result.data["id"] == "instance-1"


def test_client_rejects_insecure_or_credentialed_base_urls():
    with pytest.raises(ValueError):
        AnatoliaCore(api_key="ac_live_" + "x" * 64, base_url="http://example.com/api")
    with pytest.raises(ValueError):
        AnatoliaCore(api_key="ac_live_" + "x" * 64, base_url="https://user:pass@example.com/api")


def test_client_percent_encodes_resource_identifiers():
    opener = Opener()
    client = AnatoliaCore(api_key="ac_live_" + "x" * 64, opener=opener)
    client.get_instance("unexpected/path?admin=true")
    request, _timeout = opener.requests[0]
    assert request.full_url.endswith("/instances/unexpected%2Fpath%3Fadmin%3Dtrue")


def test_delete_requires_and_sends_exact_resource_name_confirmation():
    opener = Opener()
    client = AnatoliaCore(api_key="ac_live_" + "x" * 64, opener=opener)
    client.delete_instance("instance-1", confirmation_name="production-vm")
    request, _timeout = opener.requests[0]
    assert request.headers["X-confirm-resource-name"] == "production-vm"


def test_webhook_verification_checks_signature_timestamp_and_event_id():
    secret = "whsec_test-secret"
    body = b'{"id":"event-1","type":"instance.created"}'
    timestamp = "1700000000"
    signature = "v1=" + hmac.new(
        secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    assert verify_webhook(
        secret=secret,
        body=body,
        webhook_id="event-1",
        timestamp=timestamp,
        signature=signature,
        now_seconds=1700000001,
    )["type"] == "instance.created"
    with pytest.raises(ValueError, match="signature"):
        verify_webhook(
            secret=secret,
            body=body,
            webhook_id="event-1",
            timestamp=timestamp,
            signature="v1=bad",
            now_seconds=1700000001,
        )
