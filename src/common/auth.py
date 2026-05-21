"""Central authorization helpers for operator-token protected actions."""

import hashlib
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


def _principal_ref(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


class AuthError(ValueError):
    pass


class AnonymousError(AuthError):
    pass


class StaleTokenError(AuthError):
    pass


class RevokedTokenError(AuthError):
    pass


class InsufficientScopeError(AuthError):
    pass


class RoleMismatchError(AuthError):
    pass


class WorkspaceMismatchError(AuthError):
    pass


@dataclass
class OperatorToken:
    sub: str
    workspace_id: str
    scopes: List[str]
    exp: float
    issued_at: float
    role: str = "operator"


class OperatorAuthService:
    def __init__(self):
        self._revoked: set[str] = set()
        self._roles: Dict[str, str] = {}
        self._audit_log: List[Dict[str, str]] = []

    def revoke(self, sub: str) -> None:
        self._revoked.add(sub)

    def set_role(self, sub: str, role: str) -> None:
        self._roles[sub] = role

    def introspect(self, token: OperatorToken) -> Dict[str, object]:
        active = (
            token.sub not in self._revoked
            and token.exp > time.time()
        )
        return {
            "active": active,
            "scope": " ".join(token.scopes),
            "workspace_id": token.workspace_id,
            "role": self._roles.get(token.sub, token.role),
            "exp": token.exp,
            "sub_ref": _principal_ref(token.sub),
        }

    def authorize_run_cancellation(
        self,
        token: Optional[OperatorToken],
        run_workspace_id: str,
        required_scope: str = "runs:cancel",
        allowed_roles: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        if allowed_roles is None:
            allowed_roles = ["operator", "admin"]
        if token is None:
            self._append_audit(
                decision="denied",
                reason="anonymous",
                sub_ref="anonymous",
                scope_ref="none",
                workspace_ref="none",
            )
            raise AnonymousError("anonymous principal")

        introspection = self.introspect(token)
        sub_ref = str(introspection["sub_ref"])
        scope_ref = _principal_ref(" ".join(sorted(token.scopes)))
        workspace_ref = _principal_ref(token.workspace_id)

        if not introspection["active"]:
            if token.exp <= time.time():
                self._append_audit(
                    decision="denied",
                    reason="stale_token",
                    sub_ref=sub_ref,
                    scope_ref=scope_ref,
                    workspace_ref=workspace_ref,
                )
                raise StaleTokenError("token expired")

            self._append_audit(
                decision="denied",
                reason="revoked_token",
                sub_ref=sub_ref,
                scope_ref=scope_ref,
                workspace_ref=workspace_ref,
            )
            raise RevokedTokenError("token revoked")

        if required_scope not in token.scopes:
            self._append_audit(
                decision="denied",
                reason="insufficient_scope",
                sub_ref=sub_ref,
                scope_ref=scope_ref,
                workspace_ref=workspace_ref,
            )
            raise InsufficientScopeError(
                f"missing scope: {_principal_ref(required_scope)}"
            )

        if introspection["role"] not in allowed_roles:
            self._append_audit(
                decision="denied",
                reason="role_mismatch",
                sub_ref=sub_ref,
                scope_ref=scope_ref,
                workspace_ref=workspace_ref,
            )
            raise RoleMismatchError("role mismatch")

        if token.workspace_id != run_workspace_id:
            self._append_audit(
                decision="denied",
                reason="workspace_mismatch",
                sub_ref=sub_ref,
                scope_ref=scope_ref,
                workspace_ref=workspace_ref,
            )
            raise WorkspaceMismatchError("workspace mismatch")

        return self._append_audit(
            decision="authorized",
            reason="all_checks_passed",
            sub_ref=sub_ref,
            scope_ref=scope_ref,
            workspace_ref=workspace_ref,
        )

    def _append_audit(
        self,
        *,
        decision: str,
        reason: str,
        sub_ref: str,
        scope_ref: str,
        workspace_ref: str,
    ) -> Dict[str, str]:
        event = {
            "event": "run_cancellation_auth",
            "decision": decision,
            "reason": reason,
            "sub_ref": sub_ref,
            "scope_ref": scope_ref,
            "workspace_ref": workspace_ref,
        }
        self._audit_log.append(event)
        return event
