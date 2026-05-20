from fastapi.testclient import TestClient

from src.api.server import create_app
from src.common.webhooks import (
    REDACTED,
    WebhookDeliveryService,
    contains_private_values,
    redact_delivery_value,
)


PRIVATE_VALUES = {
    "Bearer runtime-secret",
    "cookie-secret",
    "endpoint-secret",
    "first-secret",
    "new-secret",
    "password-secret",
    "query-secret",
    "response-secret",
    "trace-secret",
}


def test_valid_delivery_redacts_records_and_callbacks():
    service = WebhookDeliveryService()
    endpoint = service.register_endpoint(
        "workspace-a",
        "https://user:password-secret@hooks.example.test/a"
        "?token=query-secret&safe=1",
        signing_secret="endpoint-secret",
        endpoint_id="endpoint-a",
    )

    record = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        endpoint_version=endpoint.version,
        event_id="evt-1",
        headers={
            "Authorization": "Bearer runtime-secret",
            "Cookie": "session=cookie-secret",
            "X-Request-ID": "req-1",
        },
        payload={
            "status": "failed",
            "access_token": "first-secret",
            "callback_url": (
                "https://example.test/callback?"
                "signature=query-secret&ok=yes&internal_trace=trace-secret"
            ),
            "nested": [{"api_key": "endpoint-secret", "visible": "kept"}],
            "internal_trace": "trace-secret",
        },
        response={"status_code": 500, "body": {"token": "response-secret"}},
    )

    assert record.status == "delivered"
    assert record.reason == "accepted"
    assert record.payload["access_token"] == REDACTED
    assert record.payload["nested"][0]["api_key"] == REDACTED
    assert record.payload["nested"][0]["visible"] == "kept"
    assert "internal_trace" not in record.payload
    assert record.headers["Authorization"] == REDACTED
    assert record.headers["Cookie"] == REDACTED
    assert record.headers["X-Request-ID"] == "req-1"
    assert record.response["body"]["token"] == REDACTED
    assert record.endpoint["url"] == (
        "https://[REDACTED]@hooks.example.test/a?"
        "token=%5BREDACTED%5D&safe=1"
    )
    assert record.callback_payload["payload"] == record.payload
    assert not contains_private_values(record.to_dict(), PRIVATE_VALUES)


def test_rejected_disabled_and_rotated_endpoints_stay_sanitized():
    service = WebhookDeliveryService()
    disabled = service.register_endpoint(
        "workspace-a",
        "https://hooks.example.test/disabled",
        signing_secret="endpoint-secret",
        enabled=False,
        endpoint_id="disabled-endpoint",
    )
    disabled_record = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=disabled.id,
        event_id="evt-disabled",
        payload={"webhook_secret": "first-secret"},
        headers={"X-Hub-Signature": "query-secret"},
    )

    assert disabled_record.status == "rejected"
    assert disabled_record.reason == "endpoint_disabled"
    assert disabled_record.payload["webhook_secret"] == REDACTED
    assert disabled_record.headers["X-Hub-Signature"] == REDACTED

    endpoint = service.register_endpoint(
        "workspace-a",
        "https://hooks.example.test/rotated",
        endpoint_id="rotated-endpoint",
    )
    stale_version = endpoint.version
    rotated = service.rotate_endpoint(endpoint.id, "new-secret")
    assert rotated.version == stale_version + 1

    rotated_record = service.record_failure(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        endpoint_version=stale_version,
        event_id="evt-rotated",
        payload={"password": "password-secret"},
        failure={"raw_headers": {"authorization": "Bearer runtime-secret"}},
    )

    assert rotated_record.status == "rejected"
    assert rotated_record.reason == "endpoint_rotated"
    assert rotated_record.payload["password"] == REDACTED
    assert "raw_headers" not in rotated_record.response
    assert not contains_private_values(
        rotated_record.to_dict(),
        PRIVATE_VALUES,
    )


def test_retry_records_are_idempotent_and_do_not_replace_first_log():
    service = WebhookDeliveryService()
    endpoint = service.register_endpoint(
        "workspace-a",
        "https://hooks.example.test/retry",
        endpoint_id="endpoint-retry",
    )

    first = service.schedule_retry(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-retry",
        attempt=2,
        payload={"token": "first-secret", "safe": "first"},
        failure={"reason": "timeout"},
    )
    duplicate = service.schedule_retry(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-retry",
        attempt=2,
        payload={"token": "new-secret", "safe": "changed"},
        failure={"reason": "changed"},
    )

    assert duplicate.id == first.id
    assert duplicate.payload == {"token": REDACTED, "safe": "first"}
    assert duplicate.response == {"reason": "timeout"}
    assert service.delivery_log(
        "workspace-a",
        endpoint.id,
        "evt-retry",
        attempt=2,
    )["payload"] == duplicate.payload


def test_workspace_isolation_does_not_expose_foreign_endpoint_metadata():
    service = WebhookDeliveryService()
    endpoint = service.register_endpoint(
        "workspace-a",
        "https://hooks.example.test/private?token=query-secret",
        signing_secret="endpoint-secret",
        endpoint_id="endpoint-private",
    )

    record = service.deliver(
        workspace_id="workspace-b",
        endpoint_id=endpoint.id,
        event_id="evt-cross",
        payload={"secret": "first-secret", "message": "visible"},
        headers={"Authorization": "Bearer runtime-secret"},
    )

    assert record.status == "rejected"
    assert record.reason == "workspace_mismatch"
    assert record.endpoint == {"id": endpoint.id}
    assert "endpoint" not in record.callback_payload
    assert record.payload == {"secret": REDACTED, "message": "visible"}
    assert "workspace-a" not in repr(record.callback_payload)
    assert "hooks.example.test" not in repr(record.callback_payload)
    assert not contains_private_values(record.to_dict(), PRIVATE_VALUES)


def test_redaction_drops_internal_url_query_and_preserves_source():
    source = {
        "items": [
            {"refresh_token": "first-secret", "name": "visible"},
            {
                "url": (
                    "https://example.test/a?api_key=query-secret"
                    "&name=ok&internal_trace=trace-secret"
                )
            },
        ],
        "private_debug": "trace-secret",
    }

    sanitized = redact_delivery_value(source)

    assert source["items"][0]["refresh_token"] == "first-secret"
    assert sanitized == {
        "items": [
            {"refresh_token": REDACTED, "name": "visible"},
            {
                "url": (
                    "https://example.test/a?"
                    "api_key=%5BREDACTED%5D&name=ok"
                )
            },
        ],
    }


def test_api_delivery_routes_return_only_sanitized_payloads():
    app = create_app()
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    registered = client.post(
        "/api/v2/webhooks/endpoints",
        headers=headers,
        json={
            "workspace_id": "workspace-api",
            "endpoint_id": "endpoint-api",
            "url": "https://hooks.example.test/a?token=query-secret",
            "signing_secret": "endpoint-secret",
        },
    )
    assert registered.status_code == 200
    assert registered.json()["url"] == (
        "https://hooks.example.test/a?token=%5BREDACTED%5D"
    )

    delivered = client.post(
        "/api/v2/webhooks/endpoint-api/deliver",
        headers=headers,
        json={
            "workspace_id": "workspace-api",
            "event_id": "evt-api",
            "payload": {"token": "first-secret", "safe": "visible"},
            "headers": {"Authorization": "Bearer runtime-secret"},
        },
    )
    body = delivered.json()

    assert delivered.status_code == 200
    assert body["payload"] == {"token": REDACTED, "safe": "visible"}
    assert not contains_private_values(body, PRIVATE_VALUES)

    rejected = client.post(
        "/api/v2/webhooks/endpoint-api/deliver",
        headers=headers,
        json={
            "workspace_id": "workspace-other",
            "event_id": "evt-api-reject",
            "payload": {"secret": "first-secret"},
        },
    )
    detail = rejected.json()["detail"]

    assert rejected.status_code == 409
    assert detail["status"] == "rejected"
    assert detail["reason"] == "workspace_mismatch"
    assert "endpoint" not in detail
    assert "workspace-api" not in repr(detail)
