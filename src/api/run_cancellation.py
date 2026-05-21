"""Run cancellation handler with injected authorization."""

from typing import Optional

from src.common.auth import OperatorAuthService, OperatorToken


def cancel_run(
    run_id: str,
    run_workspace_id: str,
    token: Optional[OperatorToken],
    auth_service: OperatorAuthService,
) -> bool:
    auth_service.authorize_run_cancellation(
        token=token,
        run_workspace_id=run_workspace_id,
    )
    return True
