from fastapi.testclient import TestClient

from src.api.server import create_app
from src.api.webhook_dispatch import webhook_dispatcher
from src.common.webhook_dispatch import WebhookDispatchService


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_valid_delivery_invokes_sender_once_and_returns_public_callback():
    calls = []
    service = WebhookDispatchService(
        delivery_sender=lambda endpoint, payload: calls.append(
            (endpoint.id, payload)
        )
        or {"status_code": 202}
    )
    endpoint = service.register_endpoint(
        workspace_id="workspace-a",
        endpoint_id="endpoint-a",
        url="https://hooks.example.test/a",
        max_deliveries=2,
        window_seconds=60,
    )

    record = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-1",
        payload={"message": "ok", "_internal_trace": "drop-me"},
    )

    assert record.status == "delivered"
    assert record.reason == "accepted"
    assert calls == [(endpoint.id, {"message": "ok"})]
    assert record.callback_payload == {
        "endpoint_id": endpoint.id,
        "event_id": "evt-1",
        "attempt": 1,
        "status": "delivered",
        "reason": "accepted",
        "payload": {"message": "ok"},
        "response": {"status_code": 202},
    }
    assert "workspace-a" not in repr(record.callback_payload)
    assert "hooks.example.test" not in repr(record.callback_payload)


def test_rate_limited_delivery_is_rejected_before_sender_runs():
    clock = FakeClock()
    calls = []
    service = WebhookDispatchService(
        clock=clock,
        delivery_sender=lambda endpoint, payload: calls.append(endpoint.id),
    )
    endpoint = service.register_endpoint(
        workspace_id="workspace-a",
        endpoint_id="endpoint-limited",
        url="https://hooks.example.test/limited",
        max_deliveries=1,
        window_seconds=60,
    )

    first = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-1",
        payload={"ok": True},
    )
    rejected = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-2",
        payload={"ok": True, "private_debug": "drop-me"},
    )

    assert first.status == "delivered"
    assert rejected.status == "rejected"
    assert rejected.reason == "endpoint_rate_limited"
    assert rejected.retry_after == 60
    assert calls == [endpoint.id]
    assert rejected.payload == {"ok": True}
    assert "private_debug" not in repr(rejected.to_dict())


def test_disabled_endpoint_is_rejected_without_delivery_work():
    calls = []
    service = WebhookDispatchService(
        delivery_sender=lambda endpoint, payload: calls.append(endpoint.id)
    )
    endpoint = service.register_endpoint(
        workspace_id="workspace-a",
        endpoint_id="endpoint-disabled",
        url="https://hooks.example.test/disabled",
        enabled=False,
    )

    record = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-disabled",
        payload={"ok": True},
    )

    assert record.status == "rejected"
    assert record.reason == "endpoint_disabled"
    assert calls == []


def test_rotated_endpoint_version_is_rejected_idempotently():
    calls = []
    service = WebhookDispatchService(
        delivery_sender=lambda endpoint, payload: calls.append(endpoint.id)
    )
    endpoint = service.register_endpoint(
        workspace_id="workspace-a",
        endpoint_id="endpoint-rotated",
        url="https://hooks.example.test/rotated",
    )
    stale_version = endpoint.version
    rotated = service.rotate_endpoint(endpoint.id)

    rejected = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        endpoint_version=stale_version,
        event_id="evt-rotated",
        payload={"ok": True},
    )
    duplicate = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        endpoint_version=rotated.version,
        event_id="evt-rotated",
        payload={"ok": False},
    )

    assert rotated.version == stale_version + 1
    assert rejected.status == "rejected"
    assert rejected.reason == "endpoint_rotated"
    assert duplicate.id == rejected.id
    assert duplicate.payload == {"ok": True}
    assert calls == []


def test_retry_attempts_are_idempotent_and_wait_for_rate_window():
    clock = FakeClock()
    calls = []
    service = WebhookDispatchService(
        clock=clock,
        delivery_sender=lambda endpoint, payload: calls.append(
            (endpoint.id, payload["attempt"])
        ),
    )
    endpoint = service.register_endpoint(
        workspace_id="workspace-a",
        endpoint_id="endpoint-retry",
        url="https://hooks.example.test/retry",
        max_deliveries=1,
        window_seconds=30,
    )

    first = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-retry",
        attempt=1,
        payload={"attempt": 1},
    )
    limited_retry = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-retry",
        attempt=2,
        payload={"attempt": 2},
    )
    duplicate_retry = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-retry",
        attempt=2,
        payload={"attempt": 999},
    )
    clock.advance(31)
    later_retry = service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint.id,
        event_id="evt-retry",
        attempt=3,
        payload={"attempt": 3},
    )

    assert first.status == "delivered"
    assert limited_retry.status == "rejected"
    assert limited_retry.reason == "endpoint_rate_limited"
    assert duplicate_retry.id == limited_retry.id
    assert duplicate_retry.payload == {"attempt": 2}
    assert later_retry.status == "delivered"
    assert calls == [(endpoint.id, 1), (endpoint.id, 3)]


def test_workspace_isolation_blocks_foreign_endpoint_and_rate_keys():
    calls = []
    service = WebhookDispatchService(
        delivery_sender=lambda endpoint, payload: calls.append(
            (endpoint.workspace_id, endpoint.id)
        )
    )
    endpoint_a = service.register_endpoint(
        workspace_id="workspace-a",
        endpoint_id="shared-name",
        url="https://hooks.example.test/a",
        max_deliveries=1,
        window_seconds=60,
    )
    endpoint_b = service.register_endpoint(
        workspace_id="workspace-b",
        endpoint_id="workspace-b-endpoint",
        url="https://hooks.example.test/b",
        max_deliveries=1,
        window_seconds=60,
    )

    service.deliver(
        workspace_id="workspace-a",
        endpoint_id=endpoint_a.id,
        event_id="evt-a",
        payload={"ok": True},
    )
    foreign = service.deliver(
        workspace_id="workspace-b",
        endpoint_id=endpoint_a.id,
        event_id="evt-foreign",
        payload={"ok": True},
    )
    local_b = service.deliver(
        workspace_id="workspace-b",
        endpoint_id=endpoint_b.id,
        event_id="evt-b",
        payload={"ok": True},
    )

    assert foreign.status == "rejected"
    assert foreign.reason == "endpoint_not_found"
    assert "workspace-a" not in repr(foreign.callback_payload)
    assert "hooks.example.test/a" not in repr(foreign.callback_payload)
    assert local_b.status == "delivered"
    assert calls == [
        ("workspace-a", endpoint_a.id),
        ("workspace-b", endpoint_b.id),
    ]


def test_api_delivery_returns_controlled_rate_limit_response():
    webhook_dispatcher.reset()
    app = create_app()
    client = TestClient(app)
    headers = {"Authorization": "Bearer test-token"}

    registered = client.post(
        "/api/v2/webhook-dispatch/endpoints",
        headers=headers,
        json={
            "workspace_id": "workspace-api",
            "endpoint_id": "endpoint-api",
            "url": "https://hooks.example.test/api",
            "max_deliveries": 1,
            "window_seconds": 60,
        },
    )
    assert registered.status_code == 200

    first = client.post(
        "/api/v2/webhook-dispatch/endpoints/endpoint-api/deliver",
        headers=headers,
        json={
            "workspace_id": "workspace-api",
            "event_id": "evt-1",
            "payload": {"ok": True},
        },
    )
    limited = client.post(
        "/api/v2/webhook-dispatch/endpoints/endpoint-api/deliver",
        headers=headers,
        json={
            "workspace_id": "workspace-api",
            "event_id": "evt-2",
            "payload": {"ok": True},
        },
    )

    assert first.status_code == 200
    assert limited.status_code == 429
    assert limited.json()["detail"]["reason"] == "endpoint_rate_limited"
