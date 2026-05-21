from fastapi.testclient import TestClient

from src.api.server import create_app
from src.api.webhooks import webhook_delivery_service
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

AUDIT_KEYS = {
    "decision",
    "reason",
    "workspace_id",
    "endpoint_id",
    "event_id",
    "attempt",
    "status",
    "retry_after",
}

FORBIDDEN_AUDIT_KEYS = {
    "authorization",
    "callback_payload",
    "config",
    "endpoint",
    "headers",
    "payload",
    "raw_payload",
    "response",
    "secret",
    "signing_secret",
    "token",
}


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def assert_fixed_audit(record, decision, reason):
    audit = record.audit
    assert set(audit) == AUDIT_KEYS
    assert audit["decision"] == decision
    assert audit["reason"] == reason
    assert audit["workspace_id"] == record.workspace_id
    assert audit["endpoint_id"] == record.endpoint_id
    assert audit["event_id"] == record.event_id
    assert audit["attempt"] == record.attempt
    assert audit["status"] == record.status
    assert record.callback_payload["audit"] == audit
    assert not (set(audit) & FORBIDDEN_AUDIT_KEYS)
    assert not contains_private_values(audit, PRIVATE_VALUES)


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
    assert_fixed_audit(record, "delivery_accepted", "accepted")
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
    assert record.reason == "endpoint_not_found"
    assert record.endpoint == {"id": endpoint.id}
    assert record.payload == {"secret": REDACTED, "message": "visible"}
    assert_fixed_audit(record, "delivery_rejected", "workspace_isolated")
    assert "workspace-a" not in repr(record.callback_payload)
    assert "hooks.example.test" not in repr(record.callback_payload)
    assert not contains_private_values(record.to_dict(), PRIVATE_VALUES)


def test_fanout_rate_limit_is_per_endpoint_before_sender_runs():
    clock = FakeClock()
    calls = []
    service = WebhookDeliveryService(
        clock=clock,
        delivery_sender=lambda endpoint, payload: calls.append(
            (endpoint.id, payload)
        ) or {"status_code": 202},
    )
    endpoint_a = service.register_endpoint(
        "workspace-a",
        "https://hooks.example.test/a",
        endpoint_id="endpoint-a",
        max_deliveries=1,
        window_seconds=60,
    )
    endpoint_b = service.register_endpoint(
        "workspace-a",
        "https://hooks.example.test/b",
        endpoint_id="endpoint-b",
        max_deliveries=2,
        window_seconds=60,
    )

    first_batch = service.fanout(
        workspace_id="workspace-a",
        event_id="evt-1",
        payload={"message": "ok", "raw_payload": "drop-me"},
    )
    second_batch = service.fanout(
        workspace_id="workspace-a",
        event_id="evt-2",
        payload={"message": "again"},
        endpoint_ids=[endpoint_a.id, endpoint_b.id],
    )

    assert [record.status for record in first_batch] == [
        "delivered",
        "delivered",
    ]
    assert [record.reason for record in second_batch] == [
        "endpoint_rate_limited",
        "accepted",
    ]
    assert second_batch[0].retry_after == 60
    assert calls == [
        ("endpoint-a", {"message": "ok"}),
        ("endpoint-b", {"message": "ok"}),
        ("endpoint-b", {"message": "again"}),
    ]


def test_retry_attempts_do_not_double_count_rate_limit_bucket():
    clock = FakeClock()
    calls = []
    service = WebhookDeliveryService(
        clock=clock,
        delivery_sender=lambda endpoint, payload: calls.append(endpoint.id),
    )
    endpoint = service.register_endpoint(
        "workspace-a",
        "https://hooks.example.test/retry",
        endpoint_id="endpoint-retry-rate",
        max_deliveries=1,
        window_seconds=30,
    )

    first = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-retry-rate",
        payload={"attempt": 1},
    )
    retry = service.schedule_retry(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-retry-rate",
        attempt=2,
        payload={"attempt": 2},
        failure={"reason": "timeout"},
    )
    duplicate_retry = service.schedule_retry(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-retry-rate",
        attempt=2,
        payload={"attempt": 999},
        failure={"reason": "changed"},
    )
    unrelated = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-other",
        payload={"attempt": 1},
    )
    clock.advance(31)
    later = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-after-window",
        payload={"attempt": 1},
    )

    assert first.status == "delivered"
    assert retry.status == "retry_scheduled"
    assert retry.reason == "retry_scheduled"
    assert_fixed_audit(retry, "retry_reused", "retry_reused")
    assert duplicate_retry.id == retry.id
    assert duplicate_retry.payload == {"attempt": 2}
    assert duplicate_retry.audit == retry.audit
    assert unrelated.status == "rejected"
    assert unrelated.reason == "endpoint_rate_limited"
    assert_fixed_audit(unrelated, "delivery_rejected", "rate_limited")
    assert later.status == "delivered"
    assert calls == [endpoint.id, endpoint.id]


def test_rate_limit_state_is_scoped_by_workspace_and_endpoint_id():
    calls = []
    service = WebhookDeliveryService(
        delivery_sender=lambda endpoint, payload: calls.append(
            (endpoint.workspace_id, endpoint.id)
        ),
    )
    endpoint_a = service.register_endpoint(
        "workspace-a",
        "https://hooks.example.test/a",
        endpoint_id="shared-endpoint",
        max_deliveries=1,
        window_seconds=60,
    )
    endpoint_b = service.register_endpoint(
        "workspace-b",
        "https://hooks.example.test/b",
        endpoint_id="shared-endpoint",
        max_deliveries=1,
        window_seconds=60,
    )

    first_a = service.deliver(
        "workspace-a",
        endpoint_a.id,
        "evt-a-1",
        {"ok": True},
    )
    first_b = service.deliver(
        "workspace-b",
        endpoint_b.id,
        "evt-b-1",
        {"ok": True},
    )
    second_a = service.deliver(
        "workspace-a",
        endpoint_a.id,
        "evt-a-2",
        {"ok": True},
    )

    assert first_a.status == "delivered"
    assert first_b.status == "delivered"
    assert second_a.status == "rejected"
    assert second_a.reason == "endpoint_rate_limited"
    assert calls == [
        ("workspace-a", "shared-endpoint"),
        ("workspace-b", "shared-endpoint"),
    ]


def test_rate_limited_records_strip_raw_payload_before_persistence():
    service = WebhookDeliveryService()
    endpoint = service.register_endpoint(
        "workspace-a",
        "https://hooks.example.test/redacted",
        endpoint_id="endpoint-redacted-limited",
        max_deliveries=1,
        window_seconds=60,
    )

    service.deliver(
        "workspace-a",
        endpoint.id,
        "evt-first",
        {"message": "ok"},
    )
    limited = service.deliver(
        "workspace-a",
        endpoint.id,
        "evt-limited",
        {
            "message": "visible",
            "raw_payload": {"token": "first-secret"},
            "internal_debug": "trace-secret",
        },
        headers={"Authorization": "Bearer runtime-secret"},
    )
    stored = service.delivery_log(
        "workspace-a",
        endpoint.id,
        "evt-limited",
    )

    assert limited.reason == "endpoint_rate_limited"
    assert_fixed_audit(limited, "delivery_rejected", "rate_limited")
    assert stored["payload"] == {"message": "visible"}
    assert stored["headers"]["Authorization"] == REDACTED
    assert stored["audit"] == limited.audit
    assert not contains_private_values(stored, PRIVATE_VALUES)


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
    webhook_delivery_service.reset()
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
    assert detail["reason"] == "endpoint_not_found"
    assert "workspace-api" not in repr(detail)


def test_api_rate_limited_delivery_returns_429_with_retry_after():
    webhook_delivery_service.reset()
    app = create_app()
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    registered = client.post(
        "/api/v2/webhooks/endpoints",
        headers=headers,
        json={
            "workspace_id": "workspace-api",
            "endpoint_id": "endpoint-api-limited",
            "url": "https://hooks.example.test/limited",
            "max_deliveries": 1,
            "window_seconds": 60,
        },
    )
    assert registered.status_code == 200

    first = client.post(
        "/api/v2/webhooks/endpoint-api-limited/deliver",
        headers=headers,
        json={
            "workspace_id": "workspace-api",
            "event_id": "evt-api-1",
            "payload": {"ok": True},
        },
    )
    limited = client.post(
        "/api/v2/webhooks/endpoint-api-limited/deliver",
        headers=headers,
        json={
            "workspace_id": "workspace-api",
            "event_id": "evt-api-2",
            "payload": {
                "ok": True,
                "raw_payload": {"token": "first-secret"},
            },
        },
    )

    assert first.status_code == 200
    assert limited.status_code == 429
    detail = limited.json()["detail"]
    assert detail["reason"] == "endpoint_rate_limited"
    assert detail["retry_after"] == 60
    assert detail["payload"] == {"ok": True}
