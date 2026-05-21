import pytest

from src.orchestrator.workflow import (
    DuplicateNodeError,
    StepStatus,
    WorkflowError,
    WorkflowManager,
    WorkflowStep,
    _node_ref,
)


AUDIT_KEYS = {"event", "node_ref", "decision", "reason"}


def step(name):
    return WorkflowStep(name, lambda: None)


def yaml_workflow(name="workflow", body=""):
    return f"""
name: {name}
description: imported workflow
{body}
"""


def assert_audit_keys(audit):
    assert set(audit) == AUDIT_KEYS


def test_add_step_rejects_duplicate_name():
    workflow = WorkflowManager().create_workflow("manual")
    workflow.add_step(step("step-a"))

    with pytest.raises(DuplicateNodeError):
        workflow.add_step(step("step-a"))


def test_add_step_duplicate_preserves_existing_steps():
    workflow = WorkflowManager().create_workflow("manual")
    first = step("step-a")
    workflow.add_step(first)

    with pytest.raises(DuplicateNodeError):
        workflow.add_step(step("step-a"))

    assert workflow.steps == [first]
    assert workflow.get_step(first.id) is first


def test_add_step_duplicate_preserves_lifecycle_state():
    workflow = WorkflowManager().create_workflow("manual")
    workflow.status = StepStatus.RUNNING
    workflow.add_step(step("step-a"))

    with pytest.raises(DuplicateNodeError):
        workflow.add_step(step("step-a"))

    assert workflow.status is StepStatus.RUNNING


def test_add_step_duplicate_audit_uses_node_ref_only():
    raw_node_id = "sensitive-step-a"
    workflow = WorkflowManager().create_workflow("manual")
    workflow.add_step(step(raw_node_id))

    with pytest.raises(DuplicateNodeError):
        workflow.add_step(step(raw_node_id))

    audit = workflow.import_audit_log[-1]
    assert_audit_keys(audit)
    assert audit["decision"] == "rejected"
    assert audit["reason"] == "duplicate_node_id"
    assert audit["node_ref"] == _node_ref(raw_node_id)
    assert raw_node_id not in str(audit)


def test_duplicate_error_exposes_only_node_ref():
    raw_node_id = "private-node-id"
    workflow = WorkflowManager().create_workflow("manual")
    workflow.add_step(step(raw_node_id))

    with pytest.raises(DuplicateNodeError) as exc:
        workflow.add_step(step(raw_node_id))

    assert exc.value.node_id_ref == _node_ref(raw_node_id)
    assert raw_node_id not in str(exc.value)
    assert _node_ref(raw_node_id) in str(exc.value)


def test_single_step_yaml_registers_successfully():
    manager = WorkflowManager()

    workflow = manager.register_from_yaml(
        yaml_workflow(body="steps:\n  - id: step-a\n")
    )

    assert [step.name for step in workflow.steps] == ["step-a"]


def test_multi_step_yaml_preserves_order():
    manager = WorkflowManager()

    workflow = manager.register_from_yaml(
        yaml_workflow(body="steps:\n  - id: step-a\n  - id: step-b\n")
    )

    assert [step.name for step in workflow.steps] == ["step-a", "step-b"]


def test_yaml_nodes_key_registers_steps():
    manager = WorkflowManager()

    workflow = manager.register_from_yaml(
        yaml_workflow(body="nodes:\n  - id: node-a\n")
    )

    assert [step.name for step in workflow.steps] == ["node-a"]


def test_yaml_description_carries_through():
    manager = WorkflowManager()

    workflow = manager.register_from_yaml(
        "name: docs\n"
        "description: documented workflow\n"
        "steps:\n"
        "  - id: step-a\n"
    )

    assert workflow.description == "documented workflow"


def test_yaml_workflow_is_retrievable_after_registration():
    manager = WorkflowManager()

    workflow = manager.register_from_yaml(
        yaml_workflow(body="steps:\n  - id: step-a\n")
    )

    assert manager.get_workflow(workflow.id) is workflow


def test_yaml_import_audit_accepts_each_step():
    manager = WorkflowManager()

    workflow = manager.register_from_yaml(
        yaml_workflow(body="steps:\n  - id: step-a\n  - id: step-b\n")
    )

    assert [entry["decision"] for entry in workflow.import_audit_log] == [
        "accepted",
        "accepted",
    ]
    assert all(set(entry) == AUDIT_KEYS for entry in workflow.import_audit_log)


def test_yaml_missing_handler_uses_noop_callable():
    manager = WorkflowManager()
    workflow = manager.register_from_yaml(
        yaml_workflow(body="steps:\n  - id: step-a\n    handler: missing.fn\n")
    )

    assert workflow.steps[0].handler() is None


def test_yaml_node_retries_and_timeout_are_applied():
    manager = WorkflowManager()

    workflow = manager.register_from_yaml(
        yaml_workflow(
            body=(
                "steps:\n"
                "  - id: step-a\n"
                "    retries: 2\n"
                "    timeout: 60\n"
            )
        )
    )

    assert workflow.steps[0].retries == 2
    assert workflow.steps[0].timeout == 60


def test_yaml_duplicate_local_nodes_raise_error():
    manager = WorkflowManager()

    with pytest.raises(DuplicateNodeError):
        manager.register_from_yaml(
            yaml_workflow(
                body="steps:\n  - id: duplicate-a\n  - id: duplicate-a\n"
            )
        )


def test_yaml_duplicate_local_nodes_are_not_stored():
    manager = WorkflowManager()
    before = manager.list_workflows()

    with pytest.raises(DuplicateNodeError):
        manager.register_from_yaml(
            yaml_workflow(body="nodes:\n  - id: dup-a\n  - id: dup-a\n")
        )

    assert manager.list_workflows() == before


def test_failed_yaml_registration_leaves_existing_workflows_unchanged():
    manager = WorkflowManager()
    existing = manager.create_workflow("existing")

    with pytest.raises(DuplicateNodeError):
        manager.register_from_yaml(
            yaml_workflow(body="steps:\n  - id: dup-a\n  - id: dup-a\n")
        )

    assert manager.list_workflows() == [existing]


def test_yaml_duplicate_error_uses_node_ref():
    manager = WorkflowManager()
    raw_node_id = "confidential-node"

    with pytest.raises(DuplicateNodeError) as exc:
        manager.register_from_yaml(
            yaml_workflow(
                body=f"steps:\n  - id: {raw_node_id}\n  - id: {raw_node_id}\n"
            )
        )

    assert exc.value.node_id_ref == _node_ref(raw_node_id)
    assert raw_node_id not in str(exc.value)


def test_imported_steps_are_prepended_before_local_steps():
    manager = WorkflowManager()
    imports = {"shared": "name: shared\nsteps:\n  - id: shared-a\n"}

    workflow = manager.register_from_yaml(
        yaml_workflow(
            body=(
                "imports:\n"
                "  - name: shared\n"
                "steps:\n"
                "  - id: local-a\n"
            )
        ),
        imports,
    )

    assert [step.name for step in workflow.steps] == ["shared-a", "local-a"]


def test_selective_import_only_includes_listed_nodes():
    manager = WorkflowManager()
    imports = {
        "shared": (
            "name: shared\n"
            "steps:\n"
            "  - id: shared-a\n"
            "  - id: shared-b\n"
        )
    }

    workflow = manager.register_from_yaml(
        yaml_workflow(
            body=(
                "imports:\n"
                "  - name: shared\n"
                "    nodes: [shared-b]\n"
                "steps:\n"
                "  - id: local-a\n"
            )
        ),
        imports,
    )

    assert [step.name for step in workflow.steps] == ["shared-b", "local-a"]
    assert "shared-a" not in [step.name for step in workflow.steps]


def test_imported_node_collision_with_local_node_rejects():
    manager = WorkflowManager()
    imports = {"shared": "name: shared\nsteps:\n  - id: step-a\n"}

    with pytest.raises(DuplicateNodeError):
        manager.register_from_yaml(
            yaml_workflow(
                body=(
                    "imports:\n"
                    "  - name: shared\n"
                    "steps:\n"
                    "  - id: step-a\n"
                )
            ),
            imports,
        )


def test_imported_node_collision_with_another_import_rejects():
    manager = WorkflowManager()
    imports = {
        "shared-a": "name: shared-a\nsteps:\n  - id: shared-step\n",
        "shared-b": "name: shared-b\nnodes:\n  - id: shared-step\n",
    }

    with pytest.raises(DuplicateNodeError):
        manager.register_from_yaml(
            yaml_workflow(
                body=(
                    "imports:\n"
                    "  - name: shared-a\n"
                    "  - name: shared-b\n"
                )
            ),
            imports,
        )


def test_import_collision_does_not_store_workflow():
    manager = WorkflowManager()
    imports = {"shared": "name: shared\nsteps:\n  - id: step-a\n"}

    with pytest.raises(DuplicateNodeError):
        manager.register_from_yaml(
            yaml_workflow(
                body="imports:\n  - name: shared\nsteps:\n  - id: step-a\n"
            ),
            imports,
        )

    assert manager.list_workflows() == []


def test_self_import_raises_workflow_error():
    manager = WorkflowManager()

    with pytest.raises(WorkflowError) as exc:
        manager.register_from_yaml(
            yaml_workflow(
                name="self-workflow",
                body="imports:\n  - name: self-workflow\n",
            ),
            {"self-workflow": "name: self-workflow\nsteps: []\n"},
        )

    assert "self_import: self-workflow" in str(exc.value)


def test_unresolved_import_raises_workflow_error():
    manager = WorkflowManager()

    with pytest.raises(WorkflowError) as exc:
        manager.register_from_yaml(
            yaml_workflow(body="imports:\n  - name: missing-import\n"),
            {},
        )

    assert "unresolved_import: missing-import" in str(exc.value)


def test_unresolved_import_error_omits_resolver_values():
    manager = WorkflowManager()
    resolver_value = "name: hidden-source\nsteps:\n  - id: hidden-node\n"

    with pytest.raises(WorkflowError) as exc:
        manager.register_from_yaml(
            yaml_workflow(body="imports:\n  - name: missing-import\n"),
            {"other": resolver_value},
        )

    assert resolver_value not in str(exc.value)
    assert "hidden-node" not in str(exc.value)


def test_duplicate_from_yaml_never_exposes_node_id_in_audit_or_error():
    manager = WorkflowManager()
    raw_node_id = "secret-yaml-node"
    captured = []
    original_create = manager.create_workflow

    def capture_create(*args, **kwargs):
        workflow = original_create(*args, **kwargs)
        captured.append(workflow)
        return workflow

    manager.create_workflow = capture_create

    with pytest.raises(DuplicateNodeError) as exc:
        manager.register_from_yaml(
            yaml_workflow(
                body=f"steps:\n  - id: {raw_node_id}\n  - id: {raw_node_id}\n"
            )
        )

    assert captured
    assert raw_node_id not in str(captured[0].import_audit_log)
    assert raw_node_id not in str(exc.value)


def test_accepted_audit_entries_have_exact_keys_and_no_raw_node_ids():
    manager = WorkflowManager()
    raw_node_id = "accepted-sensitive-node"

    workflow = manager.register_from_yaml(
        yaml_workflow(body=f"steps:\n  - id: {raw_node_id}\n")
    )

    audit = workflow.import_audit_log[-1]
    assert_audit_keys(audit)
    assert audit["decision"] == "accepted"
    assert raw_node_id not in str(audit)


def test_rejected_audit_entries_have_exact_keys_and_no_raw_node_ids():
    manager = WorkflowManager()
    raw_node_id = "rejected-sensitive-node"
    captured = []
    original_create = manager.create_workflow

    def capture_create(*args, **kwargs):
        workflow = original_create(*args, **kwargs)
        captured.append(workflow)
        return workflow

    manager.create_workflow = capture_create

    with pytest.raises(DuplicateNodeError):
        manager.register_from_yaml(
            yaml_workflow(
                body=f"steps:\n  - id: {raw_node_id}\n  - id: {raw_node_id}\n"
            )
        )

    audit = captured[0].import_audit_log[-1]
    assert_audit_keys(audit)
    assert audit["decision"] == "rejected"
    assert raw_node_id not in str(audit)


def test_no_raw_node_ids_appear_in_any_successful_audit_entry():
    manager = WorkflowManager()
    raw_node_ids = ["private-a", "private-b"]

    workflow = manager.register_from_yaml(
        yaml_workflow(body="steps:\n  - id: private-a\n  - id: private-b\n")
    )

    audit_text = str(workflow.import_audit_log)
    assert all(raw_node_id not in audit_text for raw_node_id in raw_node_ids)


def test_string_node_form_is_supported():
    manager = WorkflowManager()

    workflow = manager.register_from_yaml(
        yaml_workflow(body="steps:\n  - string-step\n")
    )

    assert [step.name for step in workflow.steps] == ["string-step"]


def test_invalid_yaml_definition_raises_workflow_error():
    manager = WorkflowManager()

    with pytest.raises(WorkflowError):
        manager.register_from_yaml("- not-a-workflow")


def test_execute_unknown_workflow_after_failed_import_returns_false():
    manager = WorkflowManager()

    with pytest.raises(DuplicateNodeError):
        manager.register_from_yaml(
            yaml_workflow(body="steps:\n  - id: step-a\n  - id: step-a\n")
        )

    assert manager.execute_workflow("unknown-workflow-id") is False


def test_yaml_duplicate_node_regression():
    """
    Regression: YAML workflow imports must reject duplicate node
    identifiers before the workflow is stored or executed.
    """
    manager = WorkflowManager()
    import_resolver = {
        "shared-steps": "name: shared-steps\nsteps:\n  - id: step-a\n"
    }
    yaml_str = yaml_workflow(
        body=(
            "imports:\n"
            "  - name: shared-steps\n"
            "steps:\n"
            "  - id: step-a\n"
        )
    )

    with pytest.raises(DuplicateNodeError) as exc:
        manager.register_from_yaml(yaml_str, import_resolver)

    assert manager.list_workflows() == []
    assert manager.execute_workflow("unknown-workflow-id") is False
    assert "step-a" not in str(exc.value)
