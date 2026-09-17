# Lab 8 — Capstone Extension: The Agent Was Fooled; the System Still Held

**Module:** 10 — Building a Layered AI Defense  
**Duration:** 75–90 minutes, in addition to the original Lab 8  
**Difficulty:** Intermediate–Advanced

---

## Objectives

By the end of this exercise you will be able to:

- Trace malicious context to a proposed action and an independently enforced boundary
- Separate workforce identity, runtime identity, task authority, and resource access
- Enforce tenant, record, action, audience, expiry, and destination limits
- Measure the maximum effect an agent can complete before a new decision is required
- Stop a task and separately revoke its authority, including queued work
- Reconstruct attempted actions, policy decisions, and completed effects
- Apply the same principles to a defensive coding assistant

---

## Prerequisites

- Python 3.10+; only the standard library is needed for the exercise code and tests
- Jupyter to run the notebook, or run the Python blocks from this folder
- Modules 6–8 and the layered-defense concepts in Module 10
- No model account, API key, live service, or external credentials required

Open `lab-08-containment.ipynb` from this `containment/` folder. If you completed
the original Lab 8, use its virtual environment and start Jupyter here.

---

## Lab Environment

A support agent is authorized to read one Alpha ticket and draft a response.
A poisoned ticket claims that compliance has authorized sending a Beta record
to an external reviewer.

```
Untrusted ticket → proposed tool action → resource authorization → effect
                           │                     │
                     task worker            broker + policy
                           └────── audit evidence ──────┘
```

The exercise injects the resulting unsafe tool requests directly. It deliberately
assumes the agent has been fooled. It tests enforcement, not whether a particular
model resists prompt injection. The unprotected and protected runs are separate.

`boundaries.py` represents a broker, protected resources, and a worker in one
Python process. Messages go to an in-memory outbox; repository actions are also
simulated. No email, network, deployment, or shell operation occurs.

**Trust model:** The instructor/operator owns broker issuance, policy, and resource
code. The simulated agent can submit tool requests but cannot edit those controls.
Runtime identity is a trusted fixture parameter, not cryptographically authenticated.
In production, place these controls in separate trusted services and bind runtime
identity to verified workload credentials. This Python harness is not a sandbox.

### Schedule

| Activity | Minutes |
|---|---:|
| Scope and unprotected baseline | 10 |
| Resource boundaries and legitimate work | 20 |
| Capability composition | 10 |
| Stop, revoke, and queued-work drill | 20 |
| Coding-agent boundary and evidence review | 15 |
| Discussion / troubleshooting buffer | 15 |

---

## Exercise 1 — Observe the Unsafe Effect

```python
from pathlib import Path
import json
import subprocess
import sys
from boundaries import (
    Broker, Resources, Worker, Denied, support_task, coding_task,
    POISONED_TICKET, unprotected_replay, attempt,
)

print("Untrusted ticket:", POISONED_TICKET)
baseline = unprotected_replay()
print(json.dumps(baseline, indent=2))
assert baseline["read"]["tenant"] == "beta"
assert baseline["outbox"][0]["ticket_id"] == "B-1"
```

The unprotected baseline completes a simulated cross-tenant disclosure. The
ticket's assertion of compliance approval is not an actual authorization grant.

Write down the initiating user's task, the attacker-controlled source, the
proposed action, and the resulting effect. Explain what a WAF would need to know
to decide whether the action belonged to the assigned task.

---

## Exercise 2 — Enforce Resource Boundaries

Read `Task`, `Broker.validate`, and `Resources.perform` in `boundaries.py`.
The trusted operator creates a grant. The proposed tool action cannot add authority.

```python
broker = Broker()
resources = Resources(broker)
task = support_task()
token = broker.issue(task)

events = [
    attempt(resources, token, task.runtime, action="read", target="B-1"),
    attempt(resources, token, task.runtime, action="send", target="A-1",
            destination="external-review@example.invalid"),
]
assert [e["reason"] for e in events] == ["tenant_boundary", "outside_task_scope"]
assert all(e["effect"] == "none" for e in events)
assert resources.outbox == []
print(json.dumps(events, indent=2))

# Legitimate work must still succeed.
assert resources.perform(token, task.runtime, "read", "A-1")["tenant"] == "alpha"
resources.perform(token, task.runtime, "draft", "A-1")
assert len(resources.drafts) == 1
```

These calls go directly to the resource, bypassing worker orchestration. This
proves the checks do not depend on a model deciding to obey its instructions.

**Questions:** Why is a valid token insufficient? Which task fields represent
purpose through enforceable permissions? What could the agent still disclose
after a permitted read if its runtime had another outbound path?

---

## Exercise 3 — Test Tool Combinations and a New Grant

The summary task cannot send anything. An operator now authorizes a separate
task to send one Alpha ticket to an approved Alpha reviewer. This is an explicit
new grant, not an expansion requested by ticket text.

```python
send_task = support_task("approved-send-1", frozenset({"read", "send"}))
send_token = broker.issue(send_task)
for target, destination, expected in [
    ("A-1", "external-review@example.invalid", "destination_boundary"),
    ("B-1", "alpha-review@example.invalid", "tenant_boundary"),
]:
    event = attempt(resources, send_token, send_task.runtime,
                    action="send", target=target, destination=destination)
    assert event["reason"] == expected
    assert event["effect"] == "none"

resources.perform(send_token, send_task.runtime, "send", "A-1",
                  "alpha-review@example.invalid")
assert resources.outbox == [{"to": "alpha-review@example.invalid", "ticket_id": "A-1"}]
```

Record the maximum completed effect under each grant: summary versus approved
send. The send interface accepts a record identifier and enforces ownership; it
does not accept arbitrary model-generated message bodies. Explain why that
restriction matters and what additional checks a free-text messaging tool needs.

This fixture does not enforce rate/cost budgets or exactly-once delivery: an
approved record could be resent before expiry. Include those limits when defining
a production maximum completed effect; the existing denial-of-wallet lab covers
consumption controls.

**Challenge:** Add a tool or destination on paper. Identify which policy, owner,
and tests must change before that capability becomes available. A connector
update is not automatic approval of new authority.

---

## Exercise 4 — Stop Execution and Revoke Authority Separately

```python
incident_task = support_task("incident-1")
incident_token = broker.issue(incident_task)
worker = Worker(resources, incident_token, incident_task.runtime)
worker.enqueue(action="draft", target="A-1")
worker.stop()
try:
    worker.run_next()
except Denied as error:
    assert str(error) == "worker_stopped"
else:
    raise AssertionError("Stopped worker executed queued work")

# Stop alone does not invalidate an issued credential.
event = attempt(resources, incident_token, incident_task.runtime, action="read")
assert event["decision"] == "allow"
broker.revoke(incident_task.task_id)
event = attempt(resources, incident_token, incident_task.runtime, action="read")
assert event["reason"] == "task_revoked" and event["effect"] == "none"

# Revocation alone does not stop a worker, but resources recheck queued work.
queued_task = support_task("incident-2")
queued_token = broker.issue(queued_task)
queued_worker = Worker(resources, queued_token, queued_task.runtime)
queued_worker.enqueue(action="draft", target="A-1")
broker.revoke(queued_task.task_id)
assert queued_worker.running
drafts_before = len(resources.drafts)
try:
    queued_worker.run_next()
except Denied as error:
    assert str(error) == "task_revoked"
else:
    raise AssertionError("Revoked authority executed queued work")
assert len(resources.drafts) == drafts_before
queued_worker.stop()

# Narrow containment preserves a different authorized task.
assert resources.perform(token, task.runtime, "read")["tenant"] == "alpha"
```

The fixture checks revocation at every resource operation. Real systems may cache
authorization or issue offline-verifiable tokens; test actual propagation and
expiry instead of assuming revocation is instantaneous. This serial simulation
does not model an operation already committed or a distributed transaction race.

**Questions:** Which completed disclosure can no longer be undone? What does
your response plan need beyond killing the agent's process?

---

## Exercise 5 — Bound the Defensive Coding Assistant

```python
code_task = coding_task()
code_token = broker.issue(code_task, audience="repository")
resources.perform(code_token, code_task.runtime, "propose_patch", "app.py",
                  audience="repository")
for action in ["merge", "deploy", "disable_tests"]:
    event = attempt(resources, code_token, code_task.runtime, action=action,
                    target="app.py", audience="repository")
    assert event["decision"] == "deny" and event["effect"] == "none"
    print(action, event["reason"])
```

Use this boundary model in Lab 09: proposing a patch does not authorize merging,
deploying, or disabling security tests. The test suite also gives a deliberately
overbroad grant and checks that an independent repository policy still refuses
those actions.

This simulation does not configure your actual coding assistant or Git host.
Before using a real assistant, inspect its filesystem, network, credential, branch,
and CI permissions. Record which boundaries are enforced and which are only
instructions. A local agent with write access can edit local tests; protected
review and independently controlled CI must catch or prevent unsafe changes.

---

## Exercise 6 — Run the Boundary Suite

```python
result = subprocess.run([sys.executable, "-m", "unittest", "-v", "test_boundaries"],
                        capture_output=True, text=True)
print(result.stdout + result.stderr)
assert result.returncode == 0
```

The 13 tests cover legitimate behavior and boundary failures, including forged
credentials, wrong runtime, wrong audience, expiry, direct resource access,
credential reuse, queued work, and the independent repository control.

Pair exercise: select one boundary, predict which test would catch its removal,
and explain why. Test any code changes in a separate copy; preserve the original
fixture and your evidence. Do not award success for blocking all legitimate work.

---

## Exercise 7 — Produce the Incident Record

```python
artifacts = Path("artifacts")
artifacts.mkdir(exist_ok=True)
(artifacts / "audit.json").write_text(json.dumps(resources.audit, indent=2))
(artifacts / "boundary-tests.txt").write_text(result.stdout + result.stderr)
report = artifacts / "incident-review.md"
if not report.exists():
    report.write_text('''# Agent Containment Review

## Authorized Task and Identities
TODO: initiating principal, runtime, task, resource, and allowed effects.

## Maximum Completed Effect
TODO: compare unprotected, summary-only, and separately approved-send scenarios.

## Evidence
| Attempt / event ID | Policy decision | Completed effect | Boundary |
|---|---|---|---|
| TODO | TODO | TODO | TODO |

## Containment
TODO: stop versus revoke, queued work, reused credential, unaffected task.

## Recovery and Residual Risk
TODO: completed disclosures, resume criteria, owner, absent production controls.

## Coding Assistant
TODO: real assistant permissions, instruction-only limits, independent enforcement.

## Peer Review
TODO: reviewer, independent check, and decision.
''')
print("Complete:", report)
```

Link specific audit events to your claims. Logs retain identity, action, destination,
policy, decision, and effect, without copying record contents or bearer tokens.
Treat logs and retrieved evidence as untrusted when another AI analyzes them.

---

## Assessment

| Criterion | Points |
|---|---:|
| Task, trust boundaries, and maximum completed effect | 20 |
| Resource enforcement and preserved legitimate behavior | 30 |
| Separate stop/revoke drill and downstream verification | 25 |
| Evidence, peer review, and production limitations | 25 |

Completion requires blocked unsafe effects, successful legitimate work, verified
credential/queue containment, and an evidence-based incident record.

## Review Questions

1. What does this replay prove, and what does it say about model robustness?
2. Why should task identity differ from the user and runtime identities?
3. Why can two individually approved tools form a dangerous combination?
4. Which boundary still works if orchestration is bypassed?
5. What remains usable after a worker stops but its credential is not revoked?
6. Which real infrastructure controls are absent from this simulation?

## Sources and Further Reading

Based on OpenAI, *Agent security in the enterprise*, August 2026, especially
printed pp. 4–5, 13–20, and 24–27. The paper provides architectural recommendations;
this exercise is an independent classroom implementation, not an OpenAI product.

- [Paper download page](https://openai.com/business/learn/agent-security-enterprise/)
- [Designing agents to resist prompt injection](https://openai.com/index/designing-agents-to-resist-prompt-injection/)

## What's Next

Attach this incident record to your Module 10 defense architecture. In Module 11,
apply the same boundary questions to the assistant preparing a security repair.
