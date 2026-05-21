import time

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.api.middleware import AuthMiddleware, PermissionService


def build_client(permission_service):
    app = FastAPI()
    calls = []
    app.add_middleware(AuthMiddleware, permission_service=permission_service)

    @app.get("/api/v2/tasks/{task_id}/monitor")
    async def monitor_task(task_id: str, request: Request):
        calls.append(task_id)
        return {
            "task_id": task_id,
            "subject": request.state.principal.subject,
            "workspace_id": request.state.principal.workspace_id,
            "client_type": request.state.principal.client_type,
        }

    @app.get("/api/v2/agents")
    async def list_agents():
        return {"status": "ok"}

    @app.get("/api/v2/task_monitor_data")
    async def task_monitor_data():
        return {"status": "legacy-ok"}

    return TestClient(app), calls


def register_monitor_credential(
    service,
    token,
    *,
    subject="operator",
    workspace_id="workspace-a",
    role="operator",
    scopes=None,
    client_type="token",
    revoked=False,
    disabled=False,
    expires_at=None,
):
    service.register_credential(
        token,
        subject=subject,
        workspace_id=workspace_id,
        workspace_role=role,
        scopes={"task_monitor:read"} if scopes is None else scopes,
        client_type=client_type,
        revoked=revoked,
        disabled=disabled,
        expires_at=expires_at,
    )


def monitor_headers(token="fresh-token", workspace_id="workspace-a"):
    return {
        "Authorization": f"Bearer {token}",
        "X-Workspace-ID": workspace_id,
    }


def test_task_monitor_revalidates_revoked_api_key_on_each_poll():
    service = PermissionService()
    register_monitor_credential(service, "fresh-token")
    client, calls = build_client(service)

    first = client.get(
        "/api/v2/tasks/task-1/monitor",
        headers=monitor_headers(),
    )
    service.revoke_credential("fresh-token")
    second = client.get(
        "/api/v2/tasks/task-1/monitor",
        headers=monitor_headers(),
    )

    assert first.status_code == 200
    assert second.status_code == 401
    assert calls == ["task-1"]


@pytest.mark.parametrize(
    ("headers", "status_code"),
    [
        ({}, 401),
        (
            {
                "Authorization": "Token fresh-token",
                "X-Workspace-ID": "workspace-a",
            },
            401,
        ),
        (monitor_headers("missing-token"), 401),
        (monitor_headers("expired-token"), 401),
        (monitor_headers("disabled-token"), 401),
        (monitor_headers("no-scope-token"), 403),
        (monitor_headers("viewer-token"), 403),
        (monitor_headers("fresh-token", "workspace-b"), 403),
    ],
)
def test_task_monitor_denies_stale_or_insufficient_principals_before_handler(
    headers, status_code
):
    service = PermissionService()
    register_monitor_credential(service, "fresh-token")
    register_monitor_credential(
        service, "expired-token", expires_at=time.time() - 1
    )
    register_monitor_credential(service, "disabled-token", disabled=True)
    register_monitor_credential(
        service, "no-scope-token", scopes={"agents:read"}
    )
    register_monitor_credential(service, "viewer-token", role="viewer")
    client, calls = build_client(service)

    response = client.get("/api/v2/tasks/task-1/monitor", headers=headers)

    assert response.status_code == status_code
    assert calls == []


def test_task_monitor_allows_authorized_api_key_and_browser_session_clients():
    service = PermissionService()
    register_monitor_credential(service, "fresh-token", subject="api-client")
    register_monitor_credential(
        service,
        "session-token",
        subject="browser-user",
        client_type="browser",
        role="admin",
    )
    client, calls = build_client(service)

    api_response = client.get(
        "/api/v2/tasks/task-1/monitor",
        headers=monitor_headers(),
    )
    session_response = client.get(
        "/api/v2/tasks/task-2/monitor",
        headers={
            "X-Workspace-ID": "workspace-a",
            "X-Session-Token": "session-token",
        },
    )

    assert api_response.status_code == 200
    assert api_response.json()["subject"] == "api-client"
    assert api_response.json()["client_type"] == "token"
    assert session_response.status_code == 200
    assert session_response.json()["subject"] == "browser-user"
    assert session_response.json()["client_type"] == "browser"
    assert calls == ["task-1", "task-2"]


def test_regular_api_paths_keep_legacy_bearer_compatibility():
    service = PermissionService()
    client, _ = build_client(service)

    response = client.get(
        "/api/v2/agents",
        headers={"Authorization": "Bearer existing-token"},
    )

    assert response.status_code == 200


def test_non_monitor_path_with_monitor_in_name_keeps_legacy_compatibility():
    service = PermissionService()
    client, _ = build_client(service)

    response = client.get(
        "/api/v2/task_monitor_data",
        headers={"Authorization": "Bearer existing-token"},
    )

    assert response.status_code == 200
