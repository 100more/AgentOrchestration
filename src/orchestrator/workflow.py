"""Workflow Manager — Defines and executes multi-step agent workflows."""

import hashlib
import importlib
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

import yaml


def _node_ref(node_id: str) -> str:
    return hashlib.sha256(node_id.encode()).hexdigest()[:12]


def _workflow_import_audit_event(
    *, node_ref: str, decision: str, reason: str
) -> Dict[str, object]:
    return {
        "event": "workflow_yaml_import_node",
        "node_ref": node_ref,
        "decision": decision,
        "reason": reason,
    }


class WorkflowError(ValueError):
    pass


class DuplicateNodeError(ValueError):
    def __init__(self, node_id: str, context: str = ""):
        self.node_id_ref = _node_ref(node_id)
        if context:
            message = (
                f"duplicate node identifier in {context}: "
                f"{self.node_id_ref}"
            )
        else:
            message = f"duplicate node identifier: {self.node_id_ref}"
        super().__init__(message)


class StepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class WorkflowStep:
    def __init__(
        self,
        name: str,
        handler: Callable,
        retries: int = 0,
        timeout: int = 300,
    ):
        self.id = str(uuid4())
        self.name = name
        self.handler = handler
        self.retries = retries
        self.timeout = timeout
        self.status = StepStatus.PENDING
        self.result: Any = None
        self.error: Optional[str] = None


class Workflow:
    def __init__(self, name: str, description: str = ""):
        self.id = str(uuid4())
        self.name = name
        self.description = description
        self.steps: List[WorkflowStep] = []
        self._step_map: Dict[str, WorkflowStep] = {}
        self.status = StepStatus.PENDING
        self._node_ids: set[str] = set()
        self.import_audit_log: List[Dict[str, object]] = []

    def add_step(self, step: WorkflowStep) -> "Workflow":
        node_ref = _node_ref(step.name)
        if step.name in self._node_ids:
            self.import_audit_log.append(
                _workflow_import_audit_event(
                    node_ref=node_ref,
                    decision="rejected",
                    reason="duplicate_node_id",
                )
            )
            raise DuplicateNodeError(step.name)
        self._node_ids.add(step.name)
        self.steps.append(step)
        self._step_map[step.id] = step
        self.import_audit_log.append(
            _workflow_import_audit_event(
                node_ref=node_ref,
                decision="accepted",
                reason="node_registered",
            )
        )
        return self

    def get_step(self, step_id: str) -> Optional[WorkflowStep]:
        return self._step_map.get(step_id)


class WorkflowManager:
    def __init__(self):
        self._workflows: Dict[str, Workflow] = {}

    def create_workflow(self, name: str, description: str = "") -> Workflow:
        workflow = Workflow(name, description)
        self._workflows[workflow.id] = workflow
        return workflow

    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        return self._workflows.get(workflow_id)

    def list_workflows(self) -> List[Workflow]:
        return list(self._workflows.values())

    def delete_workflow(self, workflow_id: str) -> bool:
        return self._workflows.pop(workflow_id, None) is not None

    def register_from_yaml(
        self,
        yaml_str: str,
        import_resolver: Optional[Dict[str, str]] = None,
    ) -> Workflow:
        definition = self._load_yaml_definition(yaml_str)
        workflow_name = str(definition.get("name") or "workflow")
        description = str(definition.get("description") or "")
        import_resolver = import_resolver or {}

        imported_nodes: List[Dict[str, object]] = []
        for import_entry in definition.get("imports", []) or []:
            import_name, node_filter = self._parse_import_entry(import_entry)
            if import_name == workflow_name:
                raise WorkflowError(f"self_import: {import_name}")
            if import_name not in import_resolver:
                raise WorkflowError(f"unresolved_import: {import_name}")

            import_definition = self._load_yaml_definition(
                import_resolver[import_name]
            )
            nodes = self._extract_node_definitions(import_definition)
            if node_filter is not None:
                allowed = set(node_filter)
                nodes = [
                    node for node in nodes
                    if self._node_name(node) in allowed
                ]
            imported_nodes.extend(nodes)

        local_nodes = self._extract_node_definitions(definition)
        workflow = self.create_workflow(workflow_name, description)
        try:
            for node in imported_nodes + local_nodes:
                workflow.add_step(self._step_from_node(node))
        except DuplicateNodeError:
            self.delete_workflow(workflow.id)
            raise
        return workflow

    def execute_workflow(self, workflow_id: str) -> bool:
        workflow = self._workflows.get(workflow_id)
        if not workflow:
            return False

        workflow.status = StepStatus.RUNNING
        for step in workflow.steps:
            step.status = StepStatus.RUNNING
            try:
                result = step.handler()
                step.result = result
                step.status = StepStatus.COMPLETED
            except Exception as e:
                step.error = str(e)
                step.status = StepStatus.FAILED
                workflow.status = StepStatus.FAILED
                return False

        workflow.status = StepStatus.COMPLETED
        return True

    def _load_yaml_definition(self, yaml_str: str) -> Dict[str, object]:
        definition = yaml.safe_load(yaml_str) or {}
        if not isinstance(definition, dict):
            raise WorkflowError("invalid_workflow_definition")
        return definition

    def _parse_import_entry(
        self, import_entry: object
    ) -> tuple[str, Optional[List[str]]]:
        if isinstance(import_entry, str):
            return import_entry, None
        if not isinstance(import_entry, dict):
            raise WorkflowError("invalid_import")
        import_name = import_entry.get("name")
        if not isinstance(import_name, str) or not import_name:
            raise WorkflowError("invalid_import")
        nodes = import_entry.get("nodes")
        if nodes is None:
            return import_name, None
        if not isinstance(nodes, list):
            raise WorkflowError("invalid_import")
        return import_name, [str(node) for node in nodes]

    def _extract_node_definitions(
        self, definition: Dict[str, object]
    ) -> List[Dict[str, object]]:
        raw_nodes = definition.get("steps", definition.get("nodes", [])) or []
        if not isinstance(raw_nodes, list):
            raise WorkflowError("invalid_nodes")

        nodes = []
        for raw_node in raw_nodes:
            if isinstance(raw_node, str):
                nodes.append({"id": raw_node})
            elif isinstance(raw_node, dict):
                nodes.append(dict(raw_node))
            else:
                raise WorkflowError("invalid_node")
        return nodes

    def _node_name(self, node: Dict[str, object]) -> str:
        node_name = node.get("id", node.get("name"))
        if not isinstance(node_name, str) or not node_name:
            raise WorkflowError("invalid_node")
        return node_name

    def _step_from_node(self, node: Dict[str, object]) -> WorkflowStep:
        return WorkflowStep(
            self._node_name(node),
            self._resolve_handler(node.get("handler")),
            retries=int(node.get("retries", 0) or 0),
            timeout=int(node.get("timeout", 300) or 300),
        )

    def _resolve_handler(self, handler_ref: object) -> Callable:
        if callable(handler_ref):
            return handler_ref
        if not isinstance(handler_ref, str) or "." not in handler_ref:
            return lambda: None

        module_name, _, attr_name = handler_ref.rpartition(".")
        try:
            module = importlib.import_module(module_name)
            handler = getattr(module, attr_name)
        except (ImportError, AttributeError):
            return lambda: None
        if not callable(handler):
            return lambda: None
        return handler

# 2019-03-27T19:58:07 update

# 2019-05-09T09:42:56 update

# 2019-12-03T10:07:42 update

# 2020-01-16T18:43:28 update

# 2020-03-20T10:40:15 update

# 2020-04-17T15:36:50 update

# 2020-05-04T14:44:01 update

# 2020-06-16T13:17:31 update

# 2020-08-05T17:00:24 update

# 2020-09-04T08:29:23 update

# 2020-09-09T17:52:02 update

# 2020-10-23T10:57:44 update

# 2020-12-05T20:55:47 update

# 2021-01-15T19:23:40 update

# 2021-02-03T20:43:12 update

# 2021-03-16T12:26:47 update

# 2021-04-20T14:33:28 update

# 2021-10-14T15:03:32 update

# 2021-10-21T17:24:55 update

# 2021-11-16T17:01:08 update

# 2021-11-22T09:51:21 update

# 2021-12-21T16:15:47 update

# 2022-03-23T16:52:27 update

# 2022-12-21T09:25:50 update

# 2023-01-09T09:55:25 update

# 2023-01-13T11:06:15 update

# 2023-01-26T11:00:59 update

# 2023-02-23T08:56:54 update

# 2023-05-17T08:07:16 update

# 2023-06-06T17:09:34 update

# 2023-06-13T10:35:28 update

# 2023-08-24T20:36:06 update

# 2023-10-30T19:10:13 update

# 2024-01-02T08:27:25 update

# 2024-01-24T12:13:15 update

# 2024-02-08T13:35:49 update

# 2024-05-07T16:09:24 update

# 2024-05-11T09:48:46 update

# 2024-05-21T19:25:41 update

# 2024-06-05T12:00:30 update

# 2024-06-25T09:40:26 update

# 2024-09-17T13:49:39 update

# 2024-10-14T17:39:35 update

# 2024-11-27T20:14:35 update

# 2024-12-25T19:31:41 update

# 2025-01-16T13:15:09 update

# 2025-02-05T14:06:59 update

# 2025-02-17T20:55:11 update

# 2025-04-30T19:36:53 update

# 2025-07-17T10:14:40 update

# 2025-08-29T12:13:15 update

# 2025-09-03T13:51:11 update

# 2025-09-19T16:08:24 update

# 2025-11-27T08:38:12 update

# 2026-01-27T13:23:38 update

# 2026-01-28T11:22:50 update
