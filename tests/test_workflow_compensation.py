import pytest

from src.orchestrator.workflow import (
    CompensationContext,
    StepStatus,
    WorkflowManager,
    WorkflowStep,
    _step_ref,
)


AUDIT_KEYS = {
    "event",
    "workflow_id",
    "step_ref",
    "compensation_event",
    "reason",
}


def make_step(name, compensator=None, retriable=(), fail=False, calls=None):
    def handler():
        if calls is not None:
            calls.append(name)
        if fail:
            raise RuntimeError("step failed")
        return name

    return WorkflowStep(
        name,
        handler,
        compensator=compensator,
        retriable_exceptions=retriable,
    )


def make_workflow(*steps):
    manager = WorkflowManager()
    workflow = manager.create_workflow("compensation-workflow")
    for step in steps:
        workflow.add_step(step)
    return manager, workflow


def compensation_events(workflow, event):
    return [
        audit for audit in workflow.compensation_audit_log
        if audit["compensation_event"] == event
    ]


def assert_audit_schema(workflow):
    for audit in workflow.compensation_audit_log:
        assert set(audit) == AUDIT_KEYS


def test_all_steps_pass_returns_true():
    manager, workflow = make_workflow(make_step("step-a"), make_step("step-b"))

    assert manager.execute_workflow(workflow.id) is True


def test_clean_run_does_not_block_workflow():
    manager, workflow = make_workflow(make_step("step-a"))

    manager.execute_workflow(workflow.id)

    assert workflow.is_blocked is False


def test_clean_run_leaves_compensation_audit_empty():
    manager, workflow = make_workflow(make_step("step-a"))

    manager.execute_workflow(workflow.id)

    assert workflow.compensation_audit_log == []


def test_step_failure_runs_completed_step_compensator():
    calls = []
    manager, workflow = make_workflow(
        make_step(
            "step-a",
            compensator=lambda ctx: calls.append(ctx.step_ref),
        ),
        make_step("step-b", fail=True),
    )

    manager.execute_workflow(workflow.id)

    assert calls == [_step_ref("step-a")]


def test_compensators_run_in_reverse_completion_order():
    calls = []
    manager, workflow = make_workflow(
        make_step("step-a", compensator=lambda ctx: calls.append("a")),
        make_step("step-b", compensator=lambda ctx: calls.append("b")),
        make_step("step-c", fail=True),
    )

    manager.execute_workflow(workflow.id)

    assert calls == ["b", "a"]


def test_failed_step_is_not_compensated():
    calls = []
    failing_step = make_step(
        "step-b",
        compensator=lambda ctx: calls.append("failed"),
        fail=True,
    )
    manager, workflow = make_workflow(
        make_step("step-a", compensator=lambda ctx: calls.append("done")),
        failing_step,
    )

    manager.execute_workflow(workflow.id)

    assert failing_step.status == StepStatus.FAILED
    assert calls == ["done"]


def test_remaining_pending_steps_are_blocked_after_failure():
    manager, workflow = make_workflow(
        make_step("step-a"),
        make_step("step-b", fail=True),
        make_step("step-c"),
        make_step("step-d"),
    )

    manager.execute_workflow(workflow.id)

    assert workflow.steps[2].status == StepStatus.BLOCKED
    assert workflow.steps[3].status == StepStatus.BLOCKED


def test_execute_workflow_returns_false_after_step_failure():
    manager, workflow = make_workflow(make_step("step-a", fail=True))

    assert manager.execute_workflow(workflow.id) is False


def test_permanent_failure_blocks_workflow():
    manager, workflow = make_workflow(make_step("step-a", fail=True))

    manager.execute_workflow(workflow.id)

    assert workflow.is_blocked is True


def test_blocked_workflow_status_is_failed():
    manager, workflow = make_workflow(make_step("step-a", fail=True))

    manager.execute_workflow(workflow.id)

    assert workflow.status == StepStatus.FAILED


def test_missing_compensator_marks_completed_steps_compensated():
    manager, workflow = make_workflow(
        make_step("step-a"),
        make_step("step-b"),
        make_step("step-c", fail=True),
    )

    manager.execute_workflow(workflow.id)

    assert workflow.steps[0].status == StepStatus.COMPENSATED
    assert workflow.steps[1].status == StepStatus.COMPENSATED


def test_missing_compensator_records_no_compensator_events():
    manager, workflow = make_workflow(
        make_step("step-a"),
        make_step("step-b", fail=True),
    )

    manager.execute_workflow(workflow.id)

    assert len(compensation_events(workflow, "no_compensator")) == 1


def test_noop_compensation_still_blocks_downstream_steps():
    manager, workflow = make_workflow(
        make_step("step-a"),
        make_step("step-b", fail=True),
        make_step("step-c"),
    )

    manager.execute_workflow(workflow.id)

    assert workflow.steps[2].status == StepStatus.BLOCKED


def test_compensator_failure_marks_step_compensation_failed():
    def broken_compensator(ctx):
        raise RuntimeError("cannot compensate")

    manager, workflow = make_workflow(
        make_step("step-a", compensator=broken_compensator),
        make_step("step-b", fail=True),
    )

    manager.execute_workflow(workflow.id)

    assert workflow.steps[0].status == StepStatus.COMPENSATION_FAILED


def test_compensator_failure_does_not_short_circuit_remaining_compensators():
    calls = []

    def broken_compensator(ctx):
        calls.append("b")
        raise RuntimeError("cannot compensate")

    manager, workflow = make_workflow(
        make_step("step-a", compensator=lambda ctx: calls.append("a")),
        make_step("step-b", compensator=broken_compensator),
        make_step("step-c", fail=True),
    )

    manager.execute_workflow(workflow.id)

    assert calls == ["b", "a"]


def test_partial_rollback_blocks_workflow():
    def broken_compensator(ctx):
        raise RuntimeError("cannot compensate")

    manager, workflow = make_workflow(
        make_step("step-a", compensator=broken_compensator),
        make_step("step-b", fail=True),
    )

    manager.execute_workflow(workflow.id)

    assert workflow.is_blocked is True


def test_partial_rollback_summary_is_audited():
    def broken_compensator(ctx):
        raise RuntimeError("cannot compensate")

    manager, workflow = make_workflow(
        make_step("step-a", compensator=broken_compensator),
        make_step("step-b", fail=True),
    )

    manager.execute_workflow(workflow.id)

    assert compensation_events(workflow, "partial_rollback")


def test_execute_after_block_returns_false_immediately():
    calls = []
    manager, workflow = make_workflow(
        make_step("step-a", fail=True, calls=calls),
        make_step("step-b", calls=calls),
    )
    manager.execute_workflow(workflow.id)

    assert manager.execute_workflow(workflow.id) is False


def test_execute_after_block_does_not_run_handlers_again():
    calls = []
    manager, workflow = make_workflow(
        make_step("step-a", fail=True, calls=calls),
        make_step("step-b", calls=calls),
    )
    manager.execute_workflow(workflow.id)
    call_count = len(calls)

    manager.execute_workflow(workflow.id)

    assert len(calls) == call_count


def test_execute_after_block_preserves_blocked_state():
    manager, workflow = make_workflow(make_step("step-a", fail=True))
    manager.execute_workflow(workflow.id)

    manager.execute_workflow(workflow.id)

    assert workflow.is_blocked is True


def test_execute_after_block_does_not_append_audit_entries():
    manager, workflow = make_workflow(make_step("step-a", fail=True))
    manager.execute_workflow(workflow.id)
    audit_count = len(workflow.compensation_audit_log)

    manager.execute_workflow(workflow.id)

    assert len(workflow.compensation_audit_log) == audit_count


def test_workflow_block_is_idempotent():
    manager, workflow = make_workflow(make_step("step-a"))

    workflow.block("first")
    workflow.block("second")

    assert workflow.is_blocked is True
    assert workflow.status == StepStatus.FAILED


def test_run_compensation_skips_already_compensated_steps():
    calls = []
    manager, workflow = make_workflow(
        make_step("step-a", compensator=lambda ctx: calls.append("a"))
    )
    step = workflow.steps[0]
    step.status = StepStatus.COMPLETED

    manager._run_compensation(workflow, [step])
    manager._run_compensation(workflow, [step])

    assert calls == ["a"]


def test_run_compensation_does_not_duplicate_audit_on_second_call():
    manager, workflow = make_workflow(make_step("step-a"))
    step = workflow.steps[0]
    step.status = StepStatus.COMPLETED

    manager._run_compensation(workflow, [step])
    audit_count = len(workflow.compensation_audit_log)
    manager._run_compensation(workflow, [step])

    assert len(workflow.compensation_audit_log) == audit_count


@pytest.mark.parametrize("status", [StepStatus.PENDING, StepStatus.FAILED])
def test_run_compensation_skips_non_completed_scopes(status):
    calls = []
    manager, workflow = make_workflow(
        make_step("step-a", compensator=lambda ctx: calls.append("a"))
    )
    step = workflow.steps[0]
    step.status = status

    manager._run_compensation(workflow, [step])

    assert calls == []


def test_retriable_exception_skips_compensation_and_blocking():
    manager, workflow = make_workflow(
        make_step(
            "step-a",
            fail=True,
            retriable=(RuntimeError,),
        )
    )

    assert manager.execute_workflow(workflow.id) is False
    assert workflow.compensation_audit_log == []
    assert workflow.is_blocked is False


def test_permanent_exception_triggers_compensation_and_blocking():
    manager, workflow = make_workflow(make_step("step-a", fail=True))

    manager.execute_workflow(workflow.id)

    assert workflow.is_blocked is True
    assert compensation_events(workflow, "rollback_complete")


def test_compensator_receives_compensation_context():
    contexts = []
    manager, workflow = make_workflow(
        make_step("step-a", compensator=lambda ctx: contexts.append(ctx)),
        make_step("step-b", fail=True),
    )

    manager.execute_workflow(workflow.id)

    assert isinstance(contexts[0], CompensationContext)
    assert contexts[0].step_ref == _step_ref("step-a")


def test_compensation_context_does_not_expose_raw_step_name():
    contexts = []
    manager, workflow = make_workflow(
        make_step("step-a", compensator=lambda ctx: contexts.append(ctx)),
        make_step("step-b", fail=True),
    )

    manager.execute_workflow(workflow.id)

    assert "step-a" not in str(contexts[0])


def test_zero_argument_compensator_is_supported():
    calls = []
    manager, workflow = make_workflow(
        make_step("step-a", compensator=lambda: calls.append("a")),
        make_step("step-b", fail=True),
    )

    manager.execute_workflow(workflow.id)

    assert calls == ["a"]


def test_step_names_never_appear_in_compensation_audit():
    manager, workflow = make_workflow(
        make_step("step-a"),
        make_step("step-b", fail=True),
        make_step("step-c"),
    )

    manager.execute_workflow(workflow.id)

    audit_text = str(workflow.compensation_audit_log)
    assert "step-a" not in audit_text
    assert "step-b" not in audit_text
    assert "step-c" not in audit_text


def test_handler_names_never_appear_in_compensation_audit():
    def sensitive_handler_name():
        return "ok"

    failing_step = WorkflowStep(
        "step-b",
        lambda: (_ for _ in ()).throw(RuntimeError("step failed")),
    )
    manager, workflow = make_workflow(
        WorkflowStep("step-a", sensitive_handler_name),
        failing_step,
    )

    manager.execute_workflow(workflow.id)

    assert "sensitive_handler_name" not in str(workflow.compensation_audit_log)


def test_each_compensation_audit_entry_has_exact_schema():
    manager, workflow = make_workflow(
        make_step("step-a"),
        make_step("step-b", fail=True),
        make_step("step-c"),
    )

    manager.execute_workflow(workflow.id)

    assert_audit_schema(workflow)


def test_step_audit_refs_match_step_refs_or_workflow_summary():
    manager, workflow = make_workflow(
        make_step("step-a"),
        make_step("step-b", fail=True),
        make_step("step-c"),
    )

    manager.execute_workflow(workflow.id)

    allowed_refs = {_step_ref("step-a"), _step_ref("step-c"), "workflow"}
    assert {
        audit["step_ref"] for audit in workflow.compensation_audit_log
    } <= allowed_refs


def test_downstream_block_audit_uses_sanitized_step_ref():
    manager, workflow = make_workflow(
        make_step("step-a"),
        make_step("step-b", fail=True),
        make_step("step-c"),
    )

    manager.execute_workflow(workflow.id)

    blocked = compensation_events(workflow, "downstream_blocked")
    assert blocked[0]["step_ref"] == _step_ref("step-c")
    assert blocked[0]["reason"] == "post_rollback_block"


def test_compensating_actions_downstream_block_regression():
    """
    Regression: after a permanent step failure, compensating actions
    must run for all COMPLETED steps in reverse order, downstream
    PENDING steps must be BLOCKED, and no further execution is possible
    after the workflow is blocked.

    Grounded in: Garcia-Molina & Salem (1987) Saga backward recovery,
    WS-BPEL 2.0 compensation handler scope invariant, TCC idempotency,
    SagaLLM (VLDB 2025) agent orchestration compensation.
    """
    calls = []
    manager, workflow = make_workflow(
        make_step(
            "step-a",
            compensator=lambda ctx: calls.append(ctx.step_ref),
        ),
        make_step("step-b", fail=True),
        make_step("step-c"),
    )

    assert manager.execute_workflow(workflow.id) is False
    assert workflow.steps[0].status == StepStatus.COMPENSATED
    assert workflow.steps[1].status == StepStatus.FAILED
    assert workflow.steps[2].status == StepStatus.BLOCKED
    assert workflow.is_blocked is True
    assert calls == [_step_ref("step-a")]

    assert manager.execute_workflow(workflow.id) is False
    assert calls == [_step_ref("step-a")]

    audit_text = str(workflow.compensation_audit_log)
    assert "step-a" not in audit_text
    assert "step-b" not in audit_text
    assert "step-c" not in audit_text
    assert compensation_events(workflow, "rollback_complete")
