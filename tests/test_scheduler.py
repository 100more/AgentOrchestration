import asyncio

import pytest

from src.orchestrator.scheduler import TaskScheduler


AUDIT_KEYS = {
    "decision",
    "reason",
    "task_id",
    "parent_id",
    "attempt",
    "revision",
    "lifecycle_state",
    "parent_attempt",
    "parent_revision",
    "parent_lifecycle_state",
}


class TestTaskScheduler:
    def setup_method(self):
        self.scheduler = TaskScheduler()

    def dequeue(self):
        return asyncio.run(self.scheduler.dequeue())

    def assert_sanitized_audit(self, audit):
        assert set(audit) == AUDIT_KEYS
        assert audit["decision"] == "retry_rejected"
        assert "payload" not in audit
        assert "config" not in audit
        assert "secret" not in audit
        assert "token" not in audit

    def test_enqueue_task(self):
        task_id = self.scheduler.enqueue({"type": "test", "payload": {}})
        assert task_id is not None

    def test_dequeue_task(self):
        self.scheduler.enqueue({"type": "test", "payload": {"data": 1}})
        task = self.dequeue()
        assert task is not None
        assert task["type"] == "test"

    def test_enqueue_multiple_priorities(self):
        self.scheduler.enqueue({"type": "low"}, priority=1)
        self.scheduler.enqueue({"type": "high"}, priority=10)
        task = self.dequeue()
        assert task["type"] == "high"

    def test_complete_task(self):
        self.scheduler.enqueue({"type": "test"})
        task = self.dequeue()
        assert self.scheduler.complete(task["id"])

    def test_fail_task_with_retry(self):
        self.scheduler.enqueue({"type": "test"})
        task = self.dequeue()
        assert self.scheduler.fail(task["id"])

    def test_parent_cancelled_before_child_failure_rejects_child_retry(self):
        parent_id = self.scheduler.enqueue({"type": "parent"})
        parent = self.dequeue()
        assert parent["id"] == parent_id
        assert self.scheduler.cancel(parent_id)

        child_id = self.scheduler.enqueue({
            "type": "child",
            "parent_id": parent_id,
            "payload": {"token": "do-not-audit"},
        })
        child = self.dequeue()

        assert child["id"] == child_id
        assert not self.scheduler.fail(child_id)
        assert child["retries"] == 0
        assert self.dequeue() is None
        assert (
            self.scheduler.get_task_state(parent_id)["lifecycle_state"]
            == "cancelled"
        )
        assert (
            self.scheduler.get_task_state(child_id)["lifecycle_state"]
            == "cancelled"
        )

        audit = self.scheduler.retry_audit()[-1]
        self.assert_sanitized_audit(audit)
        assert audit["reason"] == "parent_cancelled"
        assert audit["task_id"] == child_id
        assert audit["parent_id"] == parent_id
        assert audit["parent_lifecycle_state"] == "cancelled"

    @pytest.mark.parametrize(
        "guard, reason",
        [
            ({"expected_attempt": 2}, "stale_child_attempt"),
            ({"expected_revision": 9}, "stale_child_revision"),
        ],
    )
    def test_stale_child_retry_guard_rejects_without_incrementing_retries(
        self,
        guard,
        reason,
    ):
        task_id = self.scheduler.enqueue({
            "type": "child",
            "attempt": 1,
            "revision": 3,
        })
        task = self.dequeue()

        assert not self.scheduler.fail(task_id, **guard)
        assert task["retries"] == 0
        assert task["attempt"] == 1
        assert task["revision"] == 3
        assert (
            self.scheduler.get_task_state(task_id)["lifecycle_state"]
            == "running"
        )
        assert self.dequeue() is None

        audit = self.scheduler.retry_audit()[-1]
        self.assert_sanitized_audit(audit)
        assert audit["reason"] == reason
        assert audit["task_id"] == task_id
        assert audit["attempt"] == 1
        assert audit["revision"] == 3
        assert audit["lifecycle_state"] == "running"

    @pytest.mark.parametrize(
        "task_snapshot, fail_snapshot",
        [
            ("cancelled", None),
            (None, "cancelling"),
        ],
    )
    def test_cancelled_parent_snapshot_rejects_child_retry(
        self,
        task_snapshot,
        fail_snapshot,
    ):
        child = {
            "type": "child",
            "parent_id": "parent-from-snapshot",
        }
        if task_snapshot is not None:
            child["parent_lifecycle_state"] = task_snapshot
        child_id = self.scheduler.enqueue(child)
        child = self.dequeue()

        assert child["id"] == child_id
        assert not self.scheduler.fail(
            child_id,
            parent_lifecycle=fail_snapshot,
        )
        assert (
            self.scheduler.get_task_state(child_id)["lifecycle_state"]
            == "cancelled"
        )
        assert self.dequeue() is None

        audit = self.scheduler.retry_audit()[-1]
        self.assert_sanitized_audit(audit)
        assert audit["reason"] == "parent_cancelled"
        assert audit["parent_id"] == "parent-from-snapshot"
        assert audit["parent_lifecycle_state"] == (
            task_snapshot or fail_snapshot
        )

    def test_stale_parent_revision_rejects_without_incrementing_retries(self):
        parent_id = self.scheduler.enqueue({"type": "parent"})
        parent = self.dequeue()
        assert self.scheduler.complete(parent["id"])

        child_id = self.scheduler.enqueue({
            "type": "child",
            "parent_id": parent_id,
            "parent_revision": 4,
        })
        child = self.dequeue()

        assert not self.scheduler.fail(child_id)
        assert child["retries"] == 0
        assert (
            self.scheduler.get_task_state(child_id)["lifecycle_state"]
            == "running"
        )
        assert self.dequeue() is None

        audit = self.scheduler.retry_audit()[-1]
        self.assert_sanitized_audit(audit)
        assert audit["reason"] == "stale_parent_revision"
        assert audit["parent_id"] == parent_id
        assert audit["parent_revision"] == 4

    def test_normal_retry_path_still_requeues_unaffected_tasks(self):
        task_id = self.scheduler.enqueue({"type": "test"})
        task = self.dequeue()

        assert self.scheduler.fail(task["id"])
        retried = self.dequeue()

        assert retried["id"] == task_id
        assert retried["type"] == "test"
        assert retried["retries"] == 1
        assert retried["attempt"] == 1
        assert retried["revision"] == 1

    def test_retry_audit_entries_are_bounded(self):
        task_id = self.scheduler.enqueue({
            "type": "child",
            "payload": {"secret": "do-not-audit"},
        })
        self.dequeue()

        for _ in range(105):
            assert not self.scheduler.fail(task_id, expected_attempt=10)

        audit = self.scheduler.retry_audit()
        assert len(audit) == 100
        assert audit[-1]["reason"] == "stale_child_attempt"
        self.assert_sanitized_audit(audit[-1])

# 2019-01-09T19:07:03 update

# 2019-02-18T12:30:02 update

# 2019-04-11T16:04:51 update

# 2019-04-17T16:25:46 update

# 2019-05-24T19:32:13 update

# 2019-07-02T12:54:25 update

# 2019-07-03T20:37:00 update

# 2019-08-21T19:37:17 update

# 2019-10-18T10:30:31 update

# 2019-10-25T09:01:38 update

# 2019-10-29T12:59:34 update

# 2019-11-05T10:07:06 update

# 2019-11-11T10:43:52 update

# 2020-01-17T13:40:02 update

# 2020-02-07T14:06:34 update

# 2020-04-03T08:53:40 update

# 2020-04-06T19:36:29 update

# 2020-05-12T11:51:05 update

# 2020-08-17T08:37:15 update

# 2020-09-15T10:39:38 update

# 2020-10-06T11:26:19 update

# 2020-10-21T13:32:43 update

# 2020-12-14T18:18:36 update

# 2020-12-23T17:15:03 update

# 2021-01-25T16:29:00 update

# 2021-02-23T11:23:50 update

# 2021-03-19T12:21:19 update

# 2021-07-29T18:48:25 update

# 2021-08-25T12:46:58 update

# 2021-09-09T16:27:13 update

# 2021-12-16T12:05:30 update

# 2022-05-07T14:05:12 update

# 2022-07-18T20:52:29 update

# 2022-07-31T18:42:26 update

# 2022-09-09T13:10:08 update

# 2023-01-04T15:16:57 update

# 2023-01-17T14:49:04 update

# 2023-02-15T13:51:30 update

# 2023-03-08T09:15:53 update

# 2023-03-23T16:32:20 update

# 2023-03-28T09:32:01 update

# 2023-05-05T17:28:22 update

# 2023-06-01T08:13:52 update

# 2023-06-20T09:58:10 update

# 2023-07-04T16:14:34 update

# 2023-07-17T20:49:40 update

# 2023-12-26T11:49:18 update

# 2024-05-27T11:00:06 update

# 2024-07-04T08:53:03 update

# 2024-07-18T16:19:02 update

# 2024-08-07T09:35:35 update

# 2024-08-22T14:32:14 update

# 2025-05-20T14:19:23 update

# 2025-07-17T17:54:48 update

# 2025-07-28T13:06:30 update

# 2025-12-22T19:05:25 update

# 2026-01-08T18:43:02 update

# 2026-01-12T16:53:28 update

# 2026-04-16T16:58:23 update
