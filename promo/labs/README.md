# Short Demo Labs — When the AI Gets Fooled

Three short demonstrations for the 30-minute course presentation. Allow ten
minutes on camera, including explanation. The actual code runs in seconds.

## Setup

Use Python 3.10+ and the full course checkout. `demo.py` imports the existing
[containment fixture](../../labs/08-Layered-Defense/containment/boundaries.py).
No packages, credentials, model access, or network connection are needed for the
terminal demos. Each command starts with fresh state and can be repeated independently.

From the course root:

```sh
python3 promo/labs/demo.py all
```

For Jupyter, open [demo.ipynb](demo.ipynb) from this directory using an existing
course environment. Each demonstration has its own cell. The notebook calls the
same functions as the terminal commands.

## Lab 1 — The Unsafe Effect

**Recording:** Slide 5, 07:00–09:00.

```sh
python3 promo/labs/demo.py exposure
```

**Show:** The assigned Alpha task, the poisoned ticket, a Beta record, and one
message in the simulated external outbox.

**Explain:** The request inside the ticket claims approval. That claim is part of
the untrusted content, not a grant from the operator.

**Say explicitly:** “We are replaying an unsafe action sequence and assuming the
agent followed the ticket. This is not a live test of a particular model.”

**Ask:** What independently enforces the original task's limits?

The vulnerable baseline returns a scripted in-memory result from the shared
teaching fixture. It illustrates the effect under investigation; it does not
establish an attack success rate or show a real external transmission.

## Lab 2 — Contain the Action and Preserve Useful Work

**Recording:** Slide 6, 09:00–14:00.

```sh
python3 promo/labs/demo.py containment
```

Walk through the output in order:

| Request | Expected Result |
|---|---|
| Read Beta ticket under the Alpha task | Denied: `tenant_boundary` |
| Send under the read-and-draft task | Denied: `outside_task_scope` |
| Read Alpha ticket | Allowed: `record_read` |
| Draft the Alpha response | Allowed: `draft_created` |
| New send grant, wrong destination | Denied: `destination_boundary` |
| New send grant, approved Alpha destination | Allowed: `message_sent` |

The operator creates the second task explicitly. Point this out before showing
the successful send. The result is one authorized simulated message, not zero
messages across the entire demonstration.

**Optional code close-up:** In `Resources.perform`, show the ownership comparison
and the destination check. Explain that the resource checks policy before adding
anything to the outbox. All code and policy in this fixture are operator-controlled.

**Ask:** What additional control is needed if the agent can use a shell or a second
messaging tool to bypass this interface?

## Lab 3 — Stop, Revoke, Verify

**Recording:** Slide 7, 14:00–17:00.

```sh
python3 promo/labs/demo.py response
```

Show these outcomes:

1. A stopped worker cannot execute its queued draft.
2. Its issued token still performs an authorized read when reused at the resource.
3. After revocation, that same credential is refused.
4. A second worker remains running after revocation, but its queued action is denied.
5. Stop that worker too; a different authorized task can still read its record.

**Ask:** What may still be active downstream after a process is terminated?

This simulation rechecks revocation synchronously on every operation. Real systems
need tests of cache behavior, delegated credentials, expiry, and already-started
operations. Stopping work cannot undo an already completed disclosure.

## Expected Console Output

[expected-output.txt](expected-output.txt) contains output captured from a successful
run of all three demos. Use it as a rehearsal reference. It is labeled as a local
simulation throughout; rerun the commands when recording your own demonstration.

## Recording and Evidence

Add `--save` to any command to retain synthetic audit evidence:

```sh
python3 promo/labs/demo.py containment --save
```

Generated files go to `promo/labs/artifacts/`, which is gitignored. Files from a
repeated scenario replace its previous evidence; copy them elsewhere if you want
to retain separate rehearsals. No real credentials or customer data are collected.

For readable screen footage, use a large terminal font and run one scenario at a
time. Record each demo separately and place it between the corresponding slides.
If the full output does not fit, use the notebook's scrollable output or split the
screen recording into close-ups. Avoid speeding through the decision lines.

## What the Demonstrations Establish

- The resource fixture denies the selected unsafe operations.
- Authorized operations still complete.
- Stopping and revocation affect different parts of the workflow.
- Audit evidence distinguishes attempts, decisions, and effects.

They do not measure model robustness, implement production identity, configure
an OS sandbox, or contact real services. Runtime identities are trusted fixture
parameters. Rate budgets and exactly-once sending are outside this small demo.

## Continue in the Full Course

- [Lab 08 containment capstone](../../labs/08-Layered-Defense/containment/lab-08-containment.md): full exercise, tests, incident record, and review questions.
- [Lab 09 verified fixes](../../labs/09-Verified-Fixes/lab-09-verified-fixes.md): reproduce a vulnerability, prepare a repair, preserve tests, and review the defensive assistant's authority.
