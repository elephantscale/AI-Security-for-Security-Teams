"""Recording-friendly demonstrations using the course's containment fixture.

Python 3.10+, standard library only. No model calls, network, email, or deployments.
Every scenario creates fresh state; no reset step or run ordering is required.
"""
import argparse
import json
from pathlib import Path
import sys

COURSE_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = COURSE_ROOT / "labs" / "08-Layered-Defense" / "containment"
if not (FIXTURE / "boundaries.py").is_file():
    raise RuntimeError("Keep promo/ inside the course checkout; the shared containment fixture is missing.")
sys.path.insert(0, str(FIXTURE))
from boundaries import (  # noqa: E402
    Broker, Resources, Worker, Denied, support_task,
    POISONED_TICKET, unprotected_replay, attempt,
)


def heading(title):
    print(f"\n{title}\n{'=' * len(title)}")
    print("LOCAL SIMULATION | synthetic data | no model or network calls\n")


def show(event, label):
    print(f"{label}\n  {event['decision'].upper()}: {event['reason']} | effect: {event['effect']}")


def exposure():
    heading("Demo 1: The unsafe effect")
    print("User task: Read Alpha ticket A-1 and draft a response.")
    print(f"Untrusted ticket: {POISONED_TICKET}\n")
    result = unprotected_replay()
    assert result["read"]["tenant"] == "beta"
    assert result["outbox"] == [{"to": "external-review@example.invalid", "ticket_id": "B-1"}]
    print("Replayed action: read Beta ticket B-1")
    print(f"  Record: {result['read']['text']}")
    print("Replayed action: send B-1 to external-review@example.invalid")
    print("  Simulated outbox: 1 message")
    print("\nObserved effect: cross-tenant disclosure in the unprotected simulation.")
    print("This is a scripted unsafe sequence, not a live model-injection result.")
    return result


def containment():
    heading("Demo 2: The resource enforces the boundary")
    broker = Broker()
    resources = Resources(broker)
    task = support_task()
    token = broker.issue(task)

    read = attempt(resources, token, task.runtime, action="read", target="B-1")
    send = attempt(resources, token, task.runtime, action="send", target="B-1",
                   destination="external-review@example.invalid")
    assert read["reason"] == "tenant_boundary"
    assert send["reason"] == "outside_task_scope"
    assert read["effect"] == send["effect"] == "none"
    show(read, "Same unsafe read: Beta ticket B-1")
    show(send, "Same unsafe send: B-1 to the external reviewer")

    owned = attempt(resources, token, task.runtime, action="read", target="A-1")
    draft = attempt(resources, token, task.runtime, action="draft", target="A-1")
    assert owned["effect"] == "record_read" and draft["effect"] == "draft_created"
    assert resources.outbox == []
    show(owned, "Legitimate work: read Alpha ticket A-1")
    show(draft, "Legitimate work: draft the Alpha response")
    print("  Summary-task outbox: 0 messages\n")

    # This grant is a trusted operator decision, not authority from ticket text.
    approved = support_task("approved-send-1", frozenset({"read", "send"}))
    approved_token = broker.issue(approved)
    print("Operator creates a NEW task: send A-1 to alpha-review@example.invalid.")
    bad = attempt(resources, approved_token, approved.runtime, action="send", target="A-1",
                  destination="external-review@example.invalid")
    assert bad["reason"] == "destination_boundary" and bad["effect"] == "none"
    show(bad, "Try an unapproved destination with the new grant")
    good = attempt(resources, approved_token, approved.runtime, action="send", target="A-1",
                   destination="alpha-review@example.invalid")
    assert good["effect"] == "message_sent"
    assert resources.outbox == [{"to": "alpha-review@example.invalid", "ticket_id": "A-1"}]
    show(good, "Send the authorized record to the approved reviewer")
    print("\nResult: unsafe paths denied; authorized read, draft, and approved send succeed.")
    return {"audit": resources.audit, "outbox": resources.outbox, "drafts": resources.drafts}


def response():
    heading("Demo 3: Stop and revoke are separate")
    broker = Broker()
    resources = Resources(broker)
    task = support_task("incident-1")
    token = broker.issue(task)
    worker = Worker(resources, token, task.runtime)
    worker.enqueue(action="draft", target="A-1")
    worker.stop()
    try:
        worker.run_next()
    except Denied as error:
        assert str(error) == "worker_stopped"
    else:
        raise AssertionError("Stopped worker executed queued work")
    show(resources.audit[-1], "Stop worker, then try its queued draft")

    still_valid = attempt(resources, token, task.runtime, action="read", target="A-1")
    assert still_valid["effect"] == "record_read"
    show(still_valid, "Reuse its issued credential directly at the resource")
    print("  Stopping the worker did not revoke its credential.\n")
    broker.revoke(task.task_id)
    revoked = attempt(resources, token, task.runtime, action="read", target="A-1")
    assert revoked["reason"] == "task_revoked" and revoked["effect"] == "none"
    show(revoked, "Revoke authority, then replay the same credential")

    queued_task = support_task("incident-2")
    queued_token = broker.issue(queued_task)
    queued_worker = Worker(resources, queued_token, queued_task.runtime)
    queued_worker.enqueue(action="draft", target="A-1")
    broker.revoke(queued_task.task_id)
    assert queued_worker.running
    try:
        queued_worker.run_next()
    except Denied as error:
        assert str(error) == "task_revoked"
    else:
        raise AssertionError("Queued work used revoked authority")
    show(resources.audit[-1], "Revoke a second task while its worker is still running")
    queued_worker.stop()
    assert not queued_worker.running
    assert resources.drafts == [] and resources.outbox == []

    other = support_task("unaffected-1")
    other_token = broker.issue(other)
    allowed = attempt(resources, other_token, other.runtime, action="read", target="A-1")
    assert allowed["effect"] == "record_read"
    show(allowed, "Check an unrelated authorized task")
    print("\nResult: stopped execution, revoked authority, and checked downstream effects.")
    return {"audit": resources.audit, "outbox": resources.outbox, "drafts": resources.drafts,
            "workers_stopped": not worker.running and not queued_worker.running}


SCENARIOS = {"exposure": exposure, "containment": containment, "response": response}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=[*SCENARIOS, "all"])
    parser.add_argument("--save", action="store_true", help="Save synthetic evidence under promo/labs/artifacts/")
    args = parser.parse_args()
    scenarios = SCENARIOS if args.scenario == "all" else {args.scenario: SCENARIOS[args.scenario]}
    for name, function in scenarios.items():
        result = function()
        if args.save:
            artifacts = Path(__file__).resolve().parent / "artifacts"
            artifacts.mkdir(exist_ok=True)
            path = artifacts / f"{name}.json"
            path.write_text(json.dumps(result, indent=2) + "\n")
            print(f"Evidence saved: {path}")


if __name__ == "__main__":
    main()
