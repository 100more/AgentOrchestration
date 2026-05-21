import asyncio

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response

from src.api.server import create_app
from src.api.middleware import UploadBoundaryMiddleware


def middleware_app(scope, receive, send):
    return None


def build_client():
    app = FastAPI()
    calls = []

    app.add_middleware(UploadBoundaryMiddleware)

    @app.post("/api/v2/upload")
    async def upload(request: Request):
        calls.append(request.state.upload_guard)
        await request.body()
        return {"status": "ok", "guard": request.state.upload_guard}

    return TestClient(app), calls


def make_request(content_type=None):
    headers = []
    if content_type is not None:
        headers.append((b"content-type", content_type.encode("latin-1")))
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/api/v2/upload",
        "raw_path": b"/api/v2/upload",
        "query_string": b"",
        "headers": headers,
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "scheme": "http",
        "state": {},
    }

    async def receive():
        return {"type": "http.request", "body": b"payload"}

    return StarletteRequest(scope, receive)


def post_upload(client, content_type=None):
    headers = {}
    if content_type is not None:
        headers["Content-Type"] = content_type
    return client.post("/api/v2/upload", content=b"payload", headers=headers)


@pytest.mark.parametrize(
    "boundary",
    [
        "abc123",
        "----WebKitFormBoundaryXXX",
        "AZaz09'()+_,-./:=?",
        "abc def",
        "x" * 70,
        "-leading-hyphen",
    ],
)
def test_valid_multipart_boundaries_pass_through(boundary):
    client, calls = build_client()

    response = post_upload(
        client, f'multipart/form-data; boundary="{boundary}"'
    )

    assert response.status_code == 200
    assert response.headers["X-Upload-Guard"] == "accepted"
    assert response.json() == {"status": "ok", "guard": "accepted"}
    assert calls == ["accepted"]


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "text/plain",
        "application/octet-stream",
    ],
)
def test_non_multipart_requests_pass_through(content_type):
    client, calls = build_client()

    response = post_upload(client, content_type)

    assert response.status_code == 200
    assert response.headers["X-Upload-Guard"] == "accepted"
    assert response.json()["guard"] == "accepted"
    assert calls == ["accepted"]


def test_request_without_content_type_passes_through():
    client, calls = build_client()

    response = post_upload(client)

    assert response.status_code == 200
    assert response.headers["X-Upload-Guard"] == "accepted"
    assert response.json()["guard"] == "accepted"
    assert calls == ["accepted"]


def test_create_app_rejects_invalid_multipart_before_auth():
    client = TestClient(create_app())

    response = client.post(
        "/api/v2/upload",
        content=b"payload",
        headers={"Content-Type": "multipart/form-data"},
    )

    assert response.status_code == 400
    assert response.headers["X-Upload-Guard"] == "rejected"
    assert response.text == "Bad Request"


@pytest.mark.parametrize(
    "content_type",
    [
        "multipart/form-data",
        "multipart/form-data; boundary=",
        "multipart/form-data; boundary=\"\"",
        f"multipart/form-data; boundary={'a' * 71}",
        "multipart/form-data; boundary=   ",
        "multipart/form-data; boundary=bad@value",
        "multipart/form-data; boundary=\"bad;value\"",
        "multipart/form-data; boundary=bad\"value",
        "multipart/form-data; boundary=<bad>",
    ],
)
def test_invalid_multipart_boundaries_reject_before_handler(content_type):
    client, calls = build_client()

    response = post_upload(client, content_type)

    assert response.status_code == 400
    assert response.text == "Bad Request"
    assert response.headers["X-Upload-Guard"] == "rejected"
    assert calls == []


def test_boundary_with_null_byte_rejects_before_call_next():
    async def run():
        middleware = UploadBoundaryMiddleware(middleware_app)
        request = make_request("multipart/form-data; boundary=bad\x00value")
        called = False

        async def call_next(request):
            nonlocal called
            called = True
            return Response("should not run")

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 400
        assert response.headers["X-Upload-Guard"] == "rejected"
        assert request.state.upload_guard is None
        assert called is False

    asyncio.run(run())


def test_rejected_request_does_not_leak_state_to_next_request():
    client, calls = build_client()

    rejected = post_upload(client, "multipart/form-data")
    accepted = post_upload(
        client, "multipart/form-data; boundary=next-request"
    )

    assert rejected.status_code == 400
    assert rejected.headers["X-Upload-Guard"] == "rejected"
    assert accepted.status_code == 200
    assert accepted.headers["X-Upload-Guard"] == "accepted"
    assert accepted.json()["guard"] == "accepted"
    assert calls == ["accepted"]


def test_valid_multipart_exception_path_clears_state():
    async def run():
        middleware = UploadBoundaryMiddleware(middleware_app)
        request = make_request("multipart/form-data; boundary=valid")

        async def call_next(request):
            assert request.state.upload_guard == "accepted"
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            await middleware.dispatch(request, call_next)

        assert request.state.upload_guard is None

    asyncio.run(run())


def test_non_multipart_exception_path_clears_state():
    async def run():
        middleware = UploadBoundaryMiddleware(middleware_app)
        request = make_request("application/json")

        async def call_next(request):
            assert request.state.upload_guard == "accepted"
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            await middleware.dispatch(request, call_next)

        assert request.state.upload_guard is None

    asyncio.run(run())


def test_accepted_request_clears_state_after_call_next():
    async def run():
        middleware = UploadBoundaryMiddleware(middleware_app)
        request = make_request("multipart/form-data; boundary=valid")

        async def call_next(request):
            assert request.state.upload_guard == "accepted"
            return Response("OK", status_code=200)

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 200
        assert response.headers["X-Upload-Guard"] == "accepted"
        assert request.state.upload_guard is None

    asyncio.run(run())


def test_rejected_request_logs_reason_without_boundary_value(caplog):
    client, calls = build_client()
    boundary = "sensitive-boundary-value-" + ("x" * 80)

    with caplog.at_level("WARNING", logger="src.api.middleware"):
        response = post_upload(
            client, f"multipart/form-data; boundary={boundary}"
        )

    messages = [record.getMessage() for record in caplog.records]
    assert response.status_code == 400
    assert calls == []
    assert any("boundary too long" in message for message in messages)
    assert all(boundary not in message for message in messages)
    assert boundary not in response.text


@pytest.mark.parametrize(
    "content_type, reason",
    [
        ("multipart/form-data", "missing boundary"),
        ("multipart/form-data; boundary=", "blank boundary"),
        (f"multipart/form-data; boundary={'a' * 71}", "boundary too long"),
        (
            "multipart/form-data; boundary=bad@value",
            "boundary contains invalid characters",
        ),
    ],
)
def test_rejected_request_logs_only_reason(caplog, content_type, reason):
    client, calls = build_client()

    with caplog.at_level("WARNING", logger="src.api.middleware"):
        response = post_upload(client, content_type)

    messages = [record.getMessage() for record in caplog.records]
    assert response.status_code == 400
    assert calls == []
    assert any(reason in message for message in messages)
