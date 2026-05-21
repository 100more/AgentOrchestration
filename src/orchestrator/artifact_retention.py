"""Artifact retention validation and cleanup scheduling audit helpers."""

import hashlib
from dataclasses import dataclass
from typing import Dict


class ArtifactRetentionError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ArtifactRetentionPolicy:
    name: str
    max_age_seconds: int
    cleanup_after_seconds: int = 0
    batch_size: int = 100
    legal_hold: bool = False


@dataclass(frozen=True)
class CleanupSchedule:
    id: str
    workflow_id: str
    policy_name: str
    run_after_seconds: int
    expected_revision: int


class ArtifactRetentionValidator:
    MAX_BATCH_SIZE = 1000

    def validate(self, policy: ArtifactRetentionPolicy) -> None:
        if policy.name.strip() == "":
            raise ArtifactRetentionError("blank_policy_name")
        if policy.legal_hold:
            raise ArtifactRetentionError("legal_hold_blocks_cleanup")
        if policy.max_age_seconds <= 0:
            raise ArtifactRetentionError("non_positive_max_age")
        if policy.cleanup_after_seconds < 0:
            raise ArtifactRetentionError("negative_cleanup_delay")
        if policy.cleanup_after_seconds > policy.max_age_seconds:
            raise ArtifactRetentionError("cleanup_after_exceeds_max_age")
        if not 1 <= policy.batch_size <= self.MAX_BATCH_SIZE:
            raise ArtifactRetentionError("invalid_batch_size")


def sanitized_policy_ref(policy_name: str) -> str:
    return hashlib.sha256(policy_name.encode("utf-8")).hexdigest()[:12]


def retention_audit_event(
    *,
    workflow_id: str,
    workflow_status: str,
    expected_revision: int | None,
    actual_revision: int,
    policy_ref: str,
    decision: str,
    reason: str,
) -> Dict[str, object]:
    return {
        "event": "artifact_retention_cleanup_schedule",
        "workflow_id": workflow_id,
        "workflow_status": workflow_status,
        "expected_revision": expected_revision,
        "actual_revision": actual_revision,
        "policy_ref": policy_ref,
        "decision": decision,
        "reason": reason,
    }
