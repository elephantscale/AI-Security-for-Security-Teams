import unittest
from dataclasses import replace
from boundaries import Broker, Resources, Worker, Denied, support_task, coding_task, unprotected_replay


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.broker = Broker()
        self.resources = Resources(self.broker)
        self.task = support_task()
        self.token = self.broker.issue(self.task)

    def call(self, **kwargs):
        return self.resources.perform(self.token, self.task.runtime, **kwargs)

    def test_unprotected_baseline_discloses_synthetic_record(self):
        result = unprotected_replay()
        self.assertEqual(result["read"]["tenant"], "beta")
        self.assertEqual(len(result["outbox"]), 1)

    def test_legitimate_read_and_draft(self):
        self.assertEqual(self.call(action="read")["tenant"], "alpha")
        self.call(action="draft")
        self.assertEqual(len(self.resources.drafts), 1)

    def test_other_tenant_denied_at_resource(self):
        with self.assertRaisesRegex(Denied, "tenant_boundary"):
            self.call(action="read", target="B-1")
        self.assertEqual(self.resources.audit[-1]["effect"], "none")

    def test_send_outside_summary_task(self):
        with self.assertRaisesRegex(Denied, "outside_task_scope"):
            self.call(action="send", destination="alpha-review@example.invalid")
        self.assertFalse(self.resources.outbox)

    def test_send_task_still_checks_destination_and_tenant(self):
        task = support_task("send-1", frozenset({"read", "send"}))
        token = self.broker.issue(task)
        for target, dest, reason in [
            ("A-1", "external-review@example.invalid", "destination_boundary"),
            ("B-1", "alpha-review@example.invalid", "tenant_boundary"),
        ]:
            with self.subTest(reason=reason), self.assertRaisesRegex(Denied, reason):
                self.resources.perform(token, task.runtime, "send", target, dest)
        self.assertFalse(self.resources.outbox)
        self.resources.perform(token, task.runtime, "send", "A-1", "alpha-review@example.invalid")
        self.assertEqual(len(self.resources.outbox), 1)

    def test_same_tenant_record_still_requires_task_scope(self):
        token = self.broker.issue(replace(self.task, ticket_ids=frozenset()))
        with self.assertRaisesRegex(Denied, "record_outside_task"):
            self.resources.perform(token, self.task.runtime, "read", "A-1")

    def test_identity_audience_and_unknown_token(self):
        for token, runtime, audience, reason in [
            (self.token, "other-runtime", "support", "runtime_mismatch"),
            (self.token, self.task.runtime, "repository", "audience_mismatch"),
            ("invented", self.task.runtime, "support", "unknown_credential"),
        ]:
            with self.subTest(reason=reason), self.assertRaisesRegex(Denied, reason):
                self.resources.perform(token, runtime, "read", audience=audience)

    def test_expiration_on_boundary(self):
        self.broker.now = 60
        with self.assertRaisesRegex(Denied, "credential_expired"):
            self.call(action="read")

    def test_stop_does_not_revoke_and_revocation_contains_reuse(self):
        worker = Worker(self.resources, self.token, self.task.runtime)
        worker.enqueue(action="draft")
        worker.stop()
        with self.assertRaisesRegex(Denied, "worker_stopped"):
            worker.run_next()
        # A copied, still-valid credential remains usable at the resource.
        self.call(action="read")
        self.broker.revoke(self.task.task_id)
        with self.assertRaisesRegex(Denied, "task_revoked"):
            self.call(action="read")
        with self.assertRaisesRegex(Denied, "task_revoked"):
            self.broker.issue(self.task)

    def test_revoke_does_not_stop_worker_but_queue_rechecks_authority(self):
        worker = Worker(self.resources, self.token, self.task.runtime)
        worker.enqueue(action="draft")
        self.broker.revoke(self.task.task_id)
        self.assertTrue(worker.running)
        with self.assertRaisesRegex(Denied, "task_revoked"):
            worker.run_next()
        self.assertFalse(self.resources.drafts)
        worker.stop()
        self.assertFalse(worker.running)

    def test_unaffected_task_continues(self):
        token = self.broker.issue(support_task("unaffected"))
        self.broker.revoke(self.task.task_id)
        self.resources.perform(token, self.task.runtime, "read")

    def test_coding_assistant_and_independent_repository_boundary(self):
        task = coding_task()
        token = self.broker.issue(task, "repository")
        self.resources.perform(token, task.runtime, "propose_patch", "app.py", audience="repository")
        for action in ["merge", "deploy", "disable_tests"]:
            with self.subTest(action=action), self.assertRaisesRegex(Denied, "outside_task_scope"):
                self.resources.perform(token, task.runtime, action, "app.py", audience="repository")
        broad = replace(task, actions=frozenset({"merge", "deploy", "disable_tests"}))
        token = self.broker.issue(broad, "repository")
        for action in broad.actions:
            with self.subTest(action=action), self.assertRaisesRegex(Denied, "independent_repository_policy"):
                self.resources.perform(token, task.runtime, action, "app.py", audience="repository")
        self.assertEqual(self.resources.effects, ["patch_proposed"])

    def test_audit_correlates_decision_and_effect_without_payload_or_token(self):
        self.call(action="draft")
        event = self.resources.audit[-1]
        for field in ["principal", "runtime", "task_id", "session_id", "action", "target",
                      "destination", "policy", "decision", "reason", "effect"]:
            self.assertIn(field, event)
        self.assertEqual(event["effect"], "draft_created")
        self.assertNotIn(self.token, str(event))
        self.assertNotIn("Synthetic Alpha support record", str(event))


if __name__ == "__main__":
    unittest.main()
