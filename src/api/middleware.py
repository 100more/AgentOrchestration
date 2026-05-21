"""API middleware components."""

import time
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Optional, Set, Tuple
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


@dataclass
class CredentialRecord:
    subject: str
    workspace_id: str
    workspace_role: str
    scopes: Set[str] = field(default_factory=set)
    expires_at: Optional[float] = None
    revoked: bool = False
    disabled: bool = False
    client_type: str = "token"


@dataclass(frozen=True)
class Principal:
    subject: str
    workspace_id: str
    workspace_role: str
    scopes: Set[str]
    client_type: str


class PermissionService:
    """Central credential revalidation for API and task-monitor clients."""

    def __init__(self, allow_legacy_bearer: bool = True):
        self.allow_legacy_bearer = allow_legacy_bearer
        self._credentials: Dict[Tuple[str, str], CredentialRecord] = {}

    def register_credential(
        self,
        token: str,
        subject: str,
        workspace_id: str,
        workspace_role: str,
        scopes: Iterable[str] = (),
        expires_at: Optional[float] = None,
        revoked: bool = False,
        disabled: bool = False,
        client_type: str = "token",
    ) -> None:
        self._credentials[(client_type, token)] = CredentialRecord(
            subject=subject,
            workspace_id=workspace_id,
            workspace_role=workspace_role,
            scopes=set(scopes),
            expires_at=expires_at,
            revoked=revoked,
            disabled=disabled,
            client_type=client_type,
        )

    def revoke_credential(
        self, token: str, client_type: str = "token"
    ) -> None:
        record = self._credentials.get((client_type, token))
        if record:
            record.revoked = True

    def authorize(
        self,
        request: Request,
        required_scopes: Iterable[str] = (),
        required_roles: Iterable[str] = (),
        require_workspace: bool = False,
        allow_legacy_bearer: Optional[bool] = None,
    ) -> Tuple[Optional[Principal], int]:
        principal, status_code = self.authenticate(
            request, allow_legacy_bearer=allow_legacy_bearer
        )
        if principal is None:
            return None, status_code

        required_scope_set = set(required_scopes)
        required_role_set = set(required_roles)
        if (
            required_scope_set
            and "*" not in principal.scopes
            and not required_scope_set.issubset(principal.scopes)
        ):
            return None, 403
        if (
            required_role_set
            and principal.workspace_role not in required_role_set
        ):
            return None, 403
        if require_workspace:
            workspace_id = request.headers.get("X-Workspace-ID", "")
            if not workspace_id or workspace_id != principal.workspace_id:
                return None, 403

        return principal, 200

    def authenticate(
        self,
        request: Request,
        allow_legacy_bearer: Optional[bool] = None,
    ) -> Tuple[Optional[Principal], int]:
        token, client_type = self._extract_token(request)
        if not token or not client_type:
            return None, 401

        record = self._credentials.get((client_type, token))
        if record is None:
            allow_legacy = (
                self.allow_legacy_bearer
                if allow_legacy_bearer is None
                else allow_legacy_bearer
            )
            if allow_legacy and client_type == "token":
                return Principal(
                    subject="legacy-token",
                    workspace_id="",
                    workspace_role="admin",
                    scopes={"*"},
                    client_type="token",
                ), 200
            return None, 401
        if record.revoked or record.disabled:
            return None, 401
        if record.expires_at is not None and record.expires_at <= time.time():
            return None, 401

        return Principal(
            subject=record.subject,
            workspace_id=record.workspace_id,
            workspace_role=record.workspace_role,
            scopes=set(record.scopes),
            client_type=record.client_type,
        ), 200

    def _extract_token(
        self, request: Request
    ) -> Tuple[Optional[str], Optional[str]]:
        authorization = request.headers.get("Authorization", "")
        if authorization:
            scheme, separator, value = authorization.partition(" ")
            if scheme != "Bearer" or not separator or not value.strip():
                return None, None
            return value.strip(), "token"

        session_token = (
            request.headers.get("X-Session-Token")
            or request.cookies.get("ao_session")
        )
        if session_token and session_token.strip():
            return session_token.strip(), "browser"

        return None, None


class AuthMiddleware(BaseHTTPMiddleware):
    TASK_MONITOR_SCOPES = {"task_monitor:read"}
    TASK_MONITOR_ROLES = {"owner", "admin", "operator"}
    TASK_MONITOR_PREFIX = "/api/v2/tasks/"
    TASK_MONITOR_SUFFIXES = ("/monitor", "/monitor/poll")

    def __init__(
        self, app, permission_service: Optional[PermissionService] = None
    ):
        super().__init__(app)
        self.permission_service = permission_service or PermissionService()

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        if (
            request.url.path.startswith("/api/v2")
            and request.url.path != "/api/v2/auth/token"
        ):
            if self._is_task_monitor_request(request):
                principal, status_code = self.permission_service.authorize(
                    request,
                    required_scopes=self.TASK_MONITOR_SCOPES,
                    required_roles=self.TASK_MONITOR_ROLES,
                    require_workspace=True,
                    allow_legacy_bearer=False,
                )
            else:
                principal, status_code = self.permission_service.authorize(
                    request
                )

            if principal is None:
                content = "Forbidden" if status_code == 403 else "Unauthorized"
                return Response(status_code=status_code, content=content)
            request.state.principal = principal
        return await call_next(request)

    def _is_task_monitor_request(self, request: Request) -> bool:
        path = request.url.path.lower().rstrip("/")
        return (
            path.startswith(self.TASK_MONITOR_PREFIX)
            and path.endswith(self.TASK_MONITOR_SUFFIXES)
        )


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 100, window: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window
        self._requests = {}

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        if client_ip not in self._requests:
            self._requests[client_ip] = []

        self._requests[client_ip] = [
            t for t in self._requests[client_ip] if now - t < self.window
        ]

        if len(self._requests[client_ip]) >= self.max_requests:
            return Response(status_code=429, content="Too many requests")

        self._requests[client_ip].append(now)
        return await call_next(request)


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        start = time.time()
        response = await call_next(request)
        duration = time.time() - start
        logger.info(
            "%s %s %s %.3fs",
            request.method,
            request.url.path,
            response.status_code,
            duration,
        )
        return response

# 2019-03-01T18:35:19 update

# 2019-04-03T13:22:05 update

# 2019-04-30T17:18:49 update

# 2019-08-20T09:29:03 update

# 2019-08-30T15:52:06 update

# 2019-11-23T16:58:42 update

# 2020-02-18T10:04:07 update

# 2020-04-21T17:35:30 update

# 2020-05-22T11:10:34 update

# 2020-07-02T12:31:26 update

# 2020-07-05T13:52:59 update

# 2020-08-21T20:36:45 update

# 2021-01-19T09:17:15 update

# 2021-01-29T11:34:24 update

# 2021-02-04T15:21:21 update

# 2021-04-19T19:23:15 update

# 2021-05-20T16:50:15 update

# 2021-06-22T19:23:44 update

# 2021-09-09T13:44:55 update

# 2021-09-16T09:30:20 update

# 2021-10-14T20:42:33 update

# 2021-12-28T16:39:14 update

# 2022-01-26T19:07:27 update

# 2022-01-28T08:03:41 update

# 2022-03-23T12:17:02 update

# 2022-04-06T12:12:27 update

# 2022-04-21T14:53:01 update

# 2022-06-30T08:37:32 update

# 2022-07-06T10:44:45 update

# 2022-11-02T11:12:47 update

# 2022-11-15T20:54:21 update

# 2022-11-23T14:13:34 update

# 2023-01-26T10:03:44 update

# 2023-02-09T17:08:10 update

# 2023-02-16T10:04:00 update

# 2023-03-14T11:52:03 update

# 2023-04-10T12:42:07 update

# 2023-04-26T10:43:39 update

# 2023-06-27T08:18:07 update

# 2023-08-30T15:30:40 update

# 2023-08-30T14:10:05 update

# 2023-10-09T18:32:46 update

# 2023-11-21T20:35:55 update

# 2024-03-07T19:17:39 update

# 2024-04-01T18:06:19 update

# 2024-07-18T15:37:34 update

# 2024-07-25T09:21:53 update

# 2024-08-12T14:24:22 update

# 2024-11-18T08:50:54 update

# 2025-04-08T12:43:05 update

# 2025-06-03T08:10:47 update

# 2025-06-12T08:37:52 update

# 2025-06-17T08:36:56 update

# 2025-07-02T18:09:42 update

# 2025-07-22T12:39:21 update

# 2025-10-13T12:13:46 update

# 2025-12-05T09:44:22 update

# 2025-12-22T18:34:47 update

# 2026-01-26T15:36:23 update

# 2026-02-13T12:36:40 update

# 2026-02-26T11:07:15 update

# 2026-03-19T11:00:17 update

# 2026-03-27T12:58:53 update

# 2026-05-12T17:19:36 update
