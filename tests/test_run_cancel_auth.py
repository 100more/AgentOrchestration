import time

import pytest

from src.api.run_cancellation import cancel_run
from src.common.auth import (
    AnonymousError,
    InsufficientScopeError,
    OperatorAuthService,
    OperatorToken,
    RevokedTokenError,
    RoleMismatchError,
    StaleTokenError,
    WorkspaceMismatchError,
    _principal_ref,
)


AUDIT_KEYS = {
    "event",
    "decision",
    "reason",
    "sub_ref",
    "scope_ref",
    "workspace_ref",
}
WORKSPACE = "ws-alpha"
OTHER_WORKSPACE = "ws-beta"


def valid_token(
    workspace=WORKSPACE,
    scopes=None,
    sub="op-1",
    ttl=300,
    role="operator",
):
    now = time.time()
    return OperatorToken(
        sub=sub,
        workspace_id=workspace,
        scopes=scopes if scopes is not None else ["runs:cancel"],
        exp=now + ttl,
        issued_at=now,
        role=role,
    )


def fresh_service():
    return OperatorAuthService()


def last_audit(service):
    return service._audit_log[-1]


def assert_audit_schema(service):
    for entry in service._audit_log:
        assert set(entry) == AUDIT_KEYS


def test_anonymous_cancel_raises_anonymous_error():
    svc = fresh_service()

    with pytest.raises(AnonymousError):
        cancel_run("run-1", WORKSPACE, None, svc)


def test_anonymous_cancel_records_denied_audit():
    svc = fresh_service()

    with pytest.raises(AnonymousError):
        cancel_run("run-1", WORKSPACE, None, svc)

    assert last_audit(svc)["decision"] == "denied"
    assert last_audit(svc)["reason"] == "anonymous"


def test_expired_token_raises_stale_token_error():
    svc = fresh_service()

    with pytest.raises(StaleTokenError):
        cancel_run("run-1", WORKSPACE, valid_token(ttl=-1), svc)


def test_expired_token_records_stale_audit_reason():
    svc = fresh_service()

    with pytest.raises(StaleTokenError):
        cancel_run("run-1", WORKSPACE, valid_token(ttl=-1), svc)

    assert last_audit(svc)["reason"] == "stale_token"


def test_expired_token_audit_does_not_expose_raw_sub():
    svc = fresh_service()
    token = valid_token(sub="op-stale", ttl=-1)

    with pytest.raises(StaleTokenError):
        cancel_run("run-1", WORKSPACE, token, svc)

    assert token.sub not in str(last_audit(svc))


def test_revoked_token_with_future_exp_raises_revoked_token_error():
    svc = fresh_service()
    token = valid_token(sub="op-revoked")
    svc.revoke(token.sub)

    with pytest.raises(RevokedTokenError):
        cancel_run("run-1", WORKSPACE, token, svc)


def test_revoked_token_records_revoked_audit_reason():
    svc = fresh_service()
    token = valid_token(sub="op-revoked")
    svc.revoke(token.sub)

    with pytest.raises(RevokedTokenError):
        cancel_run("run-1", WORKSPACE, token, svc)

    assert last_audit(svc)["reason"] == "revoked_token"


def test_revoked_token_audit_does_not_expose_raw_sub():
    svc = fresh_service()
    token = valid_token(sub="op-revoked")
    svc.revoke(token.sub)

    with pytest.raises(RevokedTokenError):
        cancel_run("run-1", WORKSPACE, token, svc)

    assert token.sub not in str(last_audit(svc))


def test_missing_cancel_scope_raises_insufficient_scope_error():
    svc = fresh_service()

    with pytest.raises(InsufficientScopeError):
        cancel_run("run-1", WORKSPACE, valid_token(scopes=[]), svc)


def test_unrelated_scope_raises_insufficient_scope_error():
    svc = fresh_service()

    with pytest.raises(InsufficientScopeError):
        cancel_run("run-1", WORKSPACE, valid_token(scopes=["runs:view"]), svc)


def test_insufficient_scope_records_audit_reason():
    svc = fresh_service()

    with pytest.raises(InsufficientScopeError):
        cancel_run("run-1", WORKSPACE, valid_token(scopes=["runs:view"]), svc)

    assert last_audit(svc)["reason"] == "insufficient_scope"


def test_wrong_role_raises_role_mismatch_error():
    svc = fresh_service()

    with pytest.raises(RoleMismatchError):
        cancel_run("run-1", WORKSPACE, valid_token(role="viewer"), svc)


def test_wrong_role_records_role_mismatch_audit_reason():
    svc = fresh_service()

    with pytest.raises(RoleMismatchError):
        cancel_run("run-1", WORKSPACE, valid_token(role="viewer"), svc)

    assert last_audit(svc)["reason"] == "role_mismatch"


def test_admin_role_can_cancel_run():
    svc = fresh_service()

    assert cancel_run("run-1", WORKSPACE, valid_token(role="admin"), svc)


def test_active_role_change_is_rechecked_on_each_cancel():
    svc = fresh_service()
    token = valid_token(sub="op-promoted", role="operator")
    svc.set_role(token.sub, "viewer")

    with pytest.raises(RoleMismatchError):
        cancel_run("run-1", WORKSPACE, token, svc)


def test_active_role_override_can_authorize_admin():
    svc = fresh_service()
    token = valid_token(sub="op-admin", role="viewer")
    svc.set_role(token.sub, "admin")

    assert cancel_run("run-1", WORKSPACE, token, svc) is True


def test_workspace_mismatch_raises_workspace_mismatch_error():
    svc = fresh_service()

    with pytest.raises(WorkspaceMismatchError):
        cancel_run("run-1", OTHER_WORKSPACE, valid_token(), svc)


def test_workspace_mismatch_denied_even_with_correct_role_and_scope():
    svc = fresh_service()
    token = valid_token(role="operator", scopes=["runs:cancel"])

    with pytest.raises(WorkspaceMismatchError):
        cancel_run("run-1", OTHER_WORKSPACE, token, svc)


def test_workspace_mismatch_records_audit_reason():
    svc = fresh_service()

    with pytest.raises(WorkspaceMismatchError):
        cancel_run("run-1", OTHER_WORKSPACE, valid_token(), svc)

    assert last_audit(svc)["reason"] == "workspace_mismatch"


def test_workspace_mismatch_audit_does_not_expose_raw_workspace():
    svc = fresh_service()

    with pytest.raises(WorkspaceMismatchError):
        cancel_run("run-1", OTHER_WORKSPACE, valid_token(), svc)

    audit_text = str(last_audit(svc))
    assert WORKSPACE not in audit_text
    assert OTHER_WORKSPACE not in audit_text


def test_valid_operator_token_cancels_run():
    svc = fresh_service()

    assert cancel_run("run-1", WORKSPACE, valid_token(), svc) is True


def test_authorized_cancel_records_authorized_audit():
    svc = fresh_service()

    cancel_run("run-1", WORKSPACE, valid_token(), svc)

    assert last_audit(svc)["decision"] == "authorized"
    assert last_audit(svc)["reason"] == "all_checks_passed"


def test_multiple_authorized_calls_append_separate_audit_entries():
    svc = fresh_service()

    cancel_run("run-1", WORKSPACE, valid_token(sub="op-1"), svc)
    cancel_run("run-2", WORKSPACE, valid_token(sub="op-2"), svc)

    assert len(svc._audit_log) == 2


def test_authorized_token_with_extra_scopes_still_succeeds():
    svc = fresh_service()
    token = valid_token(scopes=["runs:cancel", "runs:view"])

    assert cancel_run("run-1", WORKSPACE, token, svc) is True


def test_introspect_returns_active_true_for_valid_token():
    svc = fresh_service()

    assert svc.introspect(valid_token())["active"] is True


def test_introspect_returns_active_false_for_revoked_future_token():
    svc = fresh_service()
    token = valid_token(sub="op-revoked")
    svc.revoke(token.sub)

    assert svc.introspect(token)["active"] is False


def test_introspect_uses_sub_ref_not_raw_sub():
    svc = fresh_service()
    token = valid_token(sub="op-private")

    result = svc.introspect(token)

    assert result["sub_ref"] == _principal_ref(token.sub)
    assert len(result["sub_ref"]) == 12
    assert token.sub not in str(result)


def test_every_audit_entry_has_exact_schema():
    svc = fresh_service()

    cancel_run("run-1", WORKSPACE, valid_token(), svc)
    with pytest.raises(AnonymousError):
        cancel_run("run-2", WORKSPACE, None, svc)

    assert_audit_schema(svc)


def test_raw_sub_never_appears_in_any_audit_entry():
    svc = fresh_service()
    token = valid_token(sub="op-sensitive")

    cancel_run("run-1", WORKSPACE, token, svc)

    assert token.sub not in str(svc._audit_log)


def test_raw_workspace_never_appears_in_any_audit_entry():
    svc = fresh_service()

    cancel_run("run-1", WORKSPACE, valid_token(), svc)

    assert WORKSPACE not in str(svc._audit_log)


def test_audit_sub_ref_matches_principal_ref():
    svc = fresh_service()
    token = valid_token(sub="op-audit")

    cancel_run("run-1", WORKSPACE, token, svc)

    assert last_audit(svc)["sub_ref"] == _principal_ref(token.sub)


def test_revoked_and_wrong_workspace_fails_as_revoked_first():
    svc = fresh_service()
    token = valid_token(sub="op-revoked")
    svc.revoke(token.sub)

    with pytest.raises(RevokedTokenError):
        cancel_run("run-1", OTHER_WORKSPACE, token, svc)


def test_stale_and_missing_scope_fails_as_stale_first():
    svc = fresh_service()
    token = valid_token(scopes=["runs:view"], ttl=-1)

    with pytest.raises(StaleTokenError):
        cancel_run("run-1", WORKSPACE, token, svc)


def test_missing_scope_and_wrong_role_fails_as_scope_first():
    svc = fresh_service()
    token = valid_token(scopes=["runs:view"], role="viewer")

    with pytest.raises(InsufficientScopeError):
        cancel_run("run-1", WORKSPACE, token, svc)


def test_role_mismatch_and_wrong_workspace_fails_as_role_first():
    svc = fresh_service()
    token = valid_token(role="viewer")

    with pytest.raises(RoleMismatchError):
        cancel_run("run-1", OTHER_WORKSPACE, token, svc)


def test_least_privilege_run_cancellation_operator_token_regression():
    """
    Regression: run cancellation must enforce least-privilege scopes
    on operator tokens. Stale, revoked, anonymous, wrong-role, and
    insufficiently-scoped principals must all be denied. Only a
    principal with a valid, non-revoked, workspace-bound token carrying
    the runs:cancel scope may cancel a run.

    Grounded in: OWASP API1:2023 BOLA, RFC 9700 token privilege
    restriction, RFC 7662 token introspection, RFC 8693 workspace
    scope binding, NIST SP 800-228 central auth dependency.
    """
    svc = fresh_service()

    with pytest.raises(AnonymousError):
        cancel_run("run-1", WORKSPACE, None, svc)

    with pytest.raises(StaleTokenError):
        cancel_run("run-1", WORKSPACE, valid_token(ttl=-1), svc)

    tok = valid_token(sub="op-revoked")
    svc.revoke("op-revoked")
    with pytest.raises(RevokedTokenError):
        cancel_run("run-1", WORKSPACE, tok, svc)

    with pytest.raises(InsufficientScopeError):
        cancel_run("run-1", WORKSPACE, valid_token(scopes=["runs:view"]), svc)

    with pytest.raises(RoleMismatchError):
        cancel_run("run-1", WORKSPACE, valid_token(role="viewer"), svc)

    with pytest.raises(WorkspaceMismatchError):
        cancel_run("run-1", OTHER_WORKSPACE, valid_token(), svc)

    assert cancel_run("run-1", WORKSPACE, valid_token(), svc) is True

    for entry in svc._audit_log:
        assert "op-" not in str(entry)
        assert WORKSPACE not in str(entry)
        assert OTHER_WORKSPACE not in str(entry)
        assert set(entry) == AUDIT_KEYS
