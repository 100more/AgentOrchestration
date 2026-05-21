import pytest

from src.orchestrator.artifact_retention import (
    ArtifactRetentionError,
    ArtifactRetentionPolicy,
    CleanupSchedule,
    sanitized_policy_ref,
)
from src.orchestrator.workflow import (
    StepStatus,
    WorkflowManager,
    WorkflowStep,
)


AUDIT_KEYS = {
    "event",
    "workflow_id",
    "workflow_status",
    "expected_revision",
    "actual_revision",
    "policy_ref",
    "decision",
    "reason",
}


def policy(name="policy-a", **overrides):
    values = {
        "name": name,
        "max_age_seconds": 3600,
        "cleanup_after_seconds": 60,
        "batch_size": 100,
        "legal_hold": False,
    }
    values.update(overrides)
    return ArtifactRetentionPolicy(**values)


def completed_workflow():
    manager = WorkflowManager()
    workflow = manager.create_workflow("artifact cleanup")
    assert manager.execute_workflow(workflow.id) is True
    assert workflow.status is StepStatus.COMPLETED
    assert workflow.revision == 2
    return manager, workflow


def assert_artifact_name_private(workflow, artifact_name):
    assert artifact_name not in str(workflow.audit_log)


def assert_audit_schema(audit):
    assert set(audit) == AUDIT_KEYS


def test_valid_policy_on_completed_workflow_schedules_successfully():
    manager, workflow = completed_workflow()

    schedule = manager.schedule_artifact_cleanup(
        workflow.id, policy(), expected_revision=workflow.revision
    )

    assert isinstance(schedule, CleanupSchedule)
    assert workflow.cleanup_schedules == [schedule]


def test_returned_cleanup_schedule_has_workflow_and_revision():
    manager, workflow = completed_workflow()

    schedule = manager.schedule_artifact_cleanup(
        workflow.id, policy(), expected_revision=workflow.revision
    )

    assert schedule.workflow_id == workflow.id
    assert schedule.expected_revision == workflow.revision
    assert schedule.run_after_seconds == 60


def test_accepted_audit_records_cleanup_scheduled_decision():
    manager, workflow = completed_workflow()
    retention_policy = policy()

    manager.schedule_artifact_cleanup(
        workflow.id, retention_policy, expected_revision=workflow.revision
    )

    audit = workflow.audit_log[-1]
    assert_audit_schema(audit)
    assert audit["decision"] == "accepted"
    assert audit["reason"] == "cleanup_scheduled"
    assert audit["policy_ref"] == sanitized_policy_ref(retention_policy.name)


def test_multiple_different_policies_can_schedule_same_workflow():
    manager, workflow = completed_workflow()

    first = manager.schedule_artifact_cleanup(workflow.id, policy("policy-a"))
    second = manager.schedule_artifact_cleanup(workflow.id, policy("policy-b"))

    assert [first, second] == workflow.cleanup_schedules
    assert [entry["decision"] for entry in workflow.audit_log] == [
        "accepted",
        "accepted",
    ]


@pytest.mark.parametrize(
    "status",
    [StepStatus.PENDING, StepStatus.RUNNING, StepStatus.FAILED],
)
def test_non_terminal_workflow_rejects_cleanup(status):
    manager = WorkflowManager()
    workflow = manager.create_workflow("not complete")
    workflow.status = status
    workflow.revision = 7

    with pytest.raises(ArtifactRetentionError) as exc:
        manager.schedule_artifact_cleanup(workflow.id, policy())

    assert exc.value.reason == "workflow_not_completed"
    assert workflow.status is status
    assert workflow.revision == 7
    assert workflow.cleanup_schedules == []
    assert workflow.audit_log[-1]["decision"] == "rejected"
    assert workflow.audit_log[-1]["reason"] == "workflow_not_completed"


def test_rejected_non_terminal_workflow_preserves_existing_state():
    manager = WorkflowManager()
    workflow = manager.create_workflow("running")
    workflow.status = StepStatus.RUNNING
    workflow.revision = 3
    before = (
        workflow.status,
        workflow.revision,
        list(workflow.cleanup_schedules),
    )

    with pytest.raises(ArtifactRetentionError):
        manager.schedule_artifact_cleanup(workflow.id, policy())

    current = (
        workflow.status,
        workflow.revision,
        workflow.cleanup_schedules,
    )
    assert current == (
        before[0],
        before[1],
        before[2],
    )


def test_stale_revision_rejects_cleanup():
    manager, workflow = completed_workflow()

    with pytest.raises(ArtifactRetentionError) as exc:
        manager.schedule_artifact_cleanup(
            workflow.id, policy(), expected_revision=workflow.revision - 1
        )

    assert exc.value.reason == "stale_workflow_revision"
    assert workflow.cleanup_schedules == []


def test_stale_revision_rejection_records_actual_revision():
    manager, workflow = completed_workflow()

    with pytest.raises(ArtifactRetentionError):
        manager.schedule_artifact_cleanup(
            workflow.id, policy(), expected_revision=workflow.revision - 1
        )

    audit = workflow.audit_log[-1]
    assert_audit_schema(audit)
    assert audit["expected_revision"] == workflow.revision - 1
    assert audit["actual_revision"] == workflow.revision
    assert audit["reason"] == "stale_workflow_revision"


def test_stale_revision_rejection_preserves_workflow_state():
    manager, workflow = completed_workflow()
    before = (
        workflow.status,
        workflow.revision,
        list(workflow.cleanup_schedules),
    )

    with pytest.raises(ArtifactRetentionError):
        manager.schedule_artifact_cleanup(
            workflow.id, policy(), expected_revision=workflow.revision - 1
        )

    current = (
        workflow.status,
        workflow.revision,
        workflow.cleanup_schedules,
    )
    assert current == (
        before[0],
        before[1],
        before[2],
    )


def test_none_expected_revision_skips_revision_check():
    manager, workflow = completed_workflow()

    schedule = manager.schedule_artifact_cleanup(
        workflow.id, policy("no-revision-check"), expected_revision=None
    )

    assert schedule.workflow_id == workflow.id
    assert workflow.cleanup_schedules == [schedule]
    assert workflow.audit_log[-1]["expected_revision"] is None


def test_duplicate_schedule_rejects_second_attempt_once():
    manager, workflow = completed_workflow()
    retention_policy = policy("single-policy")
    first = manager.schedule_artifact_cleanup(
        workflow.id, retention_policy, expected_revision=workflow.revision
    )

    with pytest.raises(ArtifactRetentionError) as exc:
        manager.schedule_artifact_cleanup(
            workflow.id, retention_policy, expected_revision=workflow.revision
        )

    assert exc.value.reason == "duplicate_cleanup_schedule"
    assert workflow.cleanup_schedules == [first]
    assert len(workflow.audit_log) == 2
    assert [event["decision"] for event in workflow.audit_log] == [
        "accepted",
        "rejected",
    ]
    assert workflow.audit_log[-1]["reason"] == "duplicate_cleanup_schedule"


@pytest.mark.parametrize(
    ("retention_policy", "reason"),
    [
        (policy("   "), "blank_policy_name"),
        (policy("legal-hold", legal_hold=True), "legal_hold_blocks_cleanup"),
        (policy("zero-age", max_age_seconds=0), "non_positive_max_age"),
        (policy("negative-age", max_age_seconds=-1), "non_positive_max_age"),
        (
            policy("negative-delay", cleanup_after_seconds=-1),
            "negative_cleanup_delay",
        ),
        (
            policy(
                "delay-past-max",
                max_age_seconds=60,
                cleanup_after_seconds=61,
            ),
            "cleanup_after_exceeds_max_age",
        ),
        (policy("zero-batch", batch_size=0), "invalid_batch_size"),
        (policy("large-batch", batch_size=1001), "invalid_batch_size"),
    ],
)
def test_policy_validation_rejects_before_state_mutation(
    retention_policy, reason
):
    manager, workflow = completed_workflow()
    before = (workflow.status, workflow.revision)

    with pytest.raises(ArtifactRetentionError) as exc:
        manager.schedule_artifact_cleanup(
            workflow.id, retention_policy, expected_revision=workflow.revision
        )

    assert exc.value.reason == reason
    assert (workflow.status, workflow.revision) == before
    assert workflow.cleanup_schedules == []
    assert workflow.audit_log[-1]["reason"] == reason


def test_policy_validation_runs_before_lifecycle_validation():
    manager = WorkflowManager()
    workflow = manager.create_workflow("pending")

    with pytest.raises(ArtifactRetentionError) as exc:
        manager.schedule_artifact_cleanup(workflow.id, policy(" "))

    assert exc.value.reason == "blank_policy_name"
    assert workflow.status is StepStatus.PENDING
    assert workflow.cleanup_schedules == []


def test_accepted_audit_never_contains_policy_name():
    manager, workflow = completed_workflow()
    retention_policy = policy("confidential-retention-policy")

    manager.schedule_artifact_cleanup(workflow.id, retention_policy)

    assert_artifact_name_private(workflow, retention_policy.name)
    assert workflow.audit_log[-1]["policy_ref"] == sanitized_policy_ref(
        retention_policy.name
    )


def test_rejected_audit_never_contains_policy_name():
    manager, workflow = completed_workflow()
    retention_policy = policy("private-policy-name", legal_hold=True)

    with pytest.raises(ArtifactRetentionError):
        manager.schedule_artifact_cleanup(workflow.id, retention_policy)

    assert_artifact_name_private(workflow, retention_policy.name)
    assert workflow.audit_log[-1]["decision"] == "rejected"


def test_audit_record_has_exact_fixed_schema():
    manager, workflow = completed_workflow()

    manager.schedule_artifact_cleanup(workflow.id, policy())

    assert_audit_schema(workflow.audit_log[-1])


def test_rejected_audit_record_has_exact_fixed_schema():
    manager, workflow = completed_workflow()

    with pytest.raises(ArtifactRetentionError):
        manager.schedule_artifact_cleanup(
            workflow.id, policy("too-large", batch_size=1001)
        )

    assert_audit_schema(workflow.audit_log[-1])


def test_workflow_not_found_rejects_without_audit_target():
    manager = WorkflowManager()

    with pytest.raises(ArtifactRetentionError) as exc:
        manager.schedule_artifact_cleanup("missing-workflow", policy())

    assert exc.value.reason == "workflow_not_found"


def test_execute_workflow_success_increments_revision():
    manager, workflow = completed_workflow()

    assert workflow.revision == 2
    assert workflow.status is StepStatus.COMPLETED


def test_execute_workflow_failure_increments_revision_on_start_and_failure():
    manager = WorkflowManager()
    workflow = manager.create_workflow("failing")

    def fail_step():
        raise RuntimeError("failed")

    workflow.add_step(WorkflowStep("fail", fail_step))

    assert manager.execute_workflow(workflow.id) is False
    assert workflow.status is StepStatus.FAILED
    assert workflow.revision == 2


def test_validator_allows_boundary_batch_size_values():
    manager, workflow = completed_workflow()

    first = manager.schedule_artifact_cleanup(
        workflow.id, policy("batch-one", batch_size=1)
    )
    second = manager.schedule_artifact_cleanup(
        workflow.id, policy("batch-max", batch_size=1000)
    )

    assert workflow.cleanup_schedules == [first, second]


def test_cleanup_scheduling_deterministic_regression():
    """
    Regression: cleanup scheduling must reject stale, duplicate,
    and non-terminal transitions without mutating workflow state.
    """
    manager, workflow = completed_workflow()
    policy_a = policy("policy-A")
    policy_b = policy("policy-B")

    manager.schedule_artifact_cleanup(
        workflow.id, policy_a, expected_revision=2
    )
    with pytest.raises(ArtifactRetentionError) as duplicate:
        manager.schedule_artifact_cleanup(
            workflow.id, policy_a, expected_revision=2
        )
    with pytest.raises(ArtifactRetentionError) as stale:
        manager.schedule_artifact_cleanup(
            workflow.id, policy_b, expected_revision=1
        )

    assert duplicate.value.reason == "duplicate_cleanup_schedule"
    assert stale.value.reason == "stale_workflow_revision"
    assert workflow.status is StepStatus.COMPLETED
    scheduled_policy_names = [
        schedule.policy_name for schedule in workflow.cleanup_schedules
    ]
    assert scheduled_policy_names == ["policy-A"]
    assert workflow.revision == 2
