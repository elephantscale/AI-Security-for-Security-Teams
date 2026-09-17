# Presenter Notes — When the AI Gets Fooled

Target duration: **30 minutes**, including ten minutes of demonstration.
These are speaking notes and transitions, not slide content or a word-for-word
30-minute script. Rehearse once with a timer and adjust explanation to the slots.

The accompanying deck has 12 slides. Keep these notes separate when converting
`../slides/promo-slides.md` to PowerPoint. Commands below assume a terminal at the course root.

## Slide 1 — When the AI Gets Fooled

**00:00–01:00 — 1 minute**

Suggested opening:

“An AI assistant can have a valid login, use an approved tool, and still perform
an action nobody authorized. Today we'll look at a support-ticket example and
ask what keeps the system under control when the assistant makes the wrong decision.”

Introduce yourself and the course. Mention that you have taught it to a group of
security specialists. Avoid adding outcomes, testimonials, or affiliations that
you cannot substantiate.

Set the promise: viewers will see an unsafe action, the boundary that blocks it,
and the evidence needed to know the control worked.

## Slide 2 — An Ordinary Ticket. An Unauthorized Request.

**01:00–03:00 — 2 minutes**

Tell the story before showing the code. Alpha and Beta are different customers.
The user assigned the assistant an Alpha support task. The ticket tries to turn
that into a Beta data-access and external-send task.

Read the short ticket excerpt. Ask “Who authorized the new action?” Pause briefly,
then answer: the ticket only *claims* approval. The trusted operator has issued
no such grant.

Explain why plausible workflow language matters. A ticket can claim a business
process depends on doing something first. That creates a security problem even
without an obvious phrase such as “ignore previous instructions.”

Transition: “The important change is that this text can now influence a system
that takes actions.”

## Slide 3 — What Changed When We Added an Agent?

**03:00–05:00 — 2 minutes**

Walk through content, interpretation, tool selection, and effect. Keep the
distinction between authentication and authorization concrete: the login may be
valid, but the record and action still need their own checks.

Connect to the viewer's experience. AppSec engineers already enforce object
ownership. Platform teams already restrict credentials and network reach. SOC
analysts already correlate events. Agentic systems add a task and an adaptive
decision-maker to that existing security work.

Explain the WAF's role carefully: it can contribute perimeter and request controls.
Whether a ticket belongs to the current tenant generally needs application
context. Avoid claiming that all WAFs have identical visibility.

Transition: “Let's write down what the resource needs to know.”

## Slide 4 — If the Agent Believes the Ticket, What Still Stops It?

**05:00–07:00 — 2 minutes**

Use the four table rows to establish the policy. The initiating person, runtime,
task, record, and destination are distinct pieces of information.

Explain that instructions help the model decide, while authorization controls
determine whether a proposed action can complete. For this demonstration, the
operator controls the broker and resource policy. The agent cannot approve itself.

State the experimental design clearly:

“I'm going to replay the unsafe actions directly. We're assuming the assistant
followed the poisoned ticket. That lets us test the enforcement even under that
failure, without relying on whether one model happens to refuse this prompt today.”

Everything uses synthetic data and in-memory effects. No real email is sent.

## Slide 5 — Demo 1: Observe the Unsafe Effect

**07:00–09:00 — 2 minutes**

Switch to the terminal or first notebook demo cell:

```sh
python3 promo/labs/demo.py exposure
```

Show the authorized task and the untrusted ticket. Then point to the Beta record
and simulated outbox. Describe the outcome as a scripted unsafe baseline.

Ask the viewer to identify the two changes in scope: another tenant's record and
an external recipient. The user's original request authorized neither.

Do not present the output as a live jailbreak, a measured model failure rate, or
a real message transmission. The fixture makes the intended failure explicit so
we can compare it against enforced controls.

Transition: “Now we'll submit those same requests to a resource that checks the task.”

## Slide 6 — Demo 2: The Resource Enforces the Boundary

**09:00–14:00 — 5 minutes**

```sh
python3 promo/labs/demo.py containment
```

Spend roughly one minute on each of these five observations:

1. **Cross-tenant read:** `tenant_boundary` rejects the Beta record. The token's
   validity did not settle the ownership question.
2. **Send under the original task:** `outside_task_scope` rejects the send. The
   summary task has read-and-draft authority only.
3. **Useful work:** Alpha read and draft both succeed. Blocking every request
   would fail the business requirement.
4. **Separate authorization:** explicitly point out that the operator issues a
   new send grant. The poisoned ticket did not create or expand that grant.
5. **Destination control:** the new grant rejects the external destination and
   permits the approved Alpha reviewer. Show the authorized completed effect.

Optionally open `Resources.perform` in the shared fixture for a short code
close-up. Point to the checks before the outbox update; do not read the full file.

The model cannot change these policies through the tool interface. In production,
they need independent protection. A single Python process does not provide an OS
sandbox or defend against an agent with unrestricted access to edit its code.

Transition: “What happens if we decide this agent must stop immediately?”

## Slide 7 — Demo 3: Stop the Worker. Revoke Its Authority.

**14:00–17:00 — 3 minutes**

```sh
python3 promo/labs/demo.py response
```

First show the stopped worker refusing queued work. Then point to the successful
read using its already-issued credential. Let that distinction land before
explaining revocation.

The subsequent replay is denied after the broker revokes the task. A second
example shows the reverse: revocation does not stop a worker, but the resource's
fresh check rejects its queued operation. Stop the worker as well.

Finish by showing the unaffected authorized task continuing. Containment should
be as narrow as the incident permits.

Mention the limits: real revocation may involve caches, delegated credentials,
and services with different token lifetimes. A completed disclosure cannot be
reversed by stopping a process. The fixture is serial and rechecks every call.

Transition: “The evidence we just saw tells us where each boundary worked.”

## Slide 8 — Put Controls Where the Effect Happens

**17:00–20:00 — 3 minutes**

Return to the slides. Walk from guidance to task policy, resource authorization,
runtime restrictions, and evidence. For each layer, give one concrete example
from the demonstration.

Introduce the question “What is the most consequential effect this agent can
complete before another independent decision is required?” Explain that a
permitted read is itself meaningful, even if the send action needs approval.

Credit OpenAI's *Agent security in the enterprise* paper for the task-authority,
completed-effect, and stop/revoke framing. Explain that it is architectural
guidance, and this course applies the ideas through independent teaching exercises.
Do not imply OpenAI sponsorship or that the demo is an OpenAI product.

Discuss one bypass path: if a shell can reach arbitrary destinations, restricting
only the messaging tool is incomplete. Bound the other path and test it too.

## Slide 9 — Apply the Same Questions Across AI Systems

**20:00–23:00 — 3 minutes**

Briefly expand from the support example to RAG, agents, API consumption, SOC
analysis, and coding assistants. Use each row as a question, not a product list.

For coding assistants, a task to propose a repair does not authorize disabling
tests, merging, or deploying. For SOC work, an assistant's conclusion needs
evidence from the underlying events. For RAG, retrieved text is evidence or
content; it does not grant tool permissions.

Avoid starting a second complex demonstration. The full course develops these
cases through the labs. The viewer should now understand why the same discipline
applies across different AI workloads.

## Slide 10 — What We Build in the Course

**23:00–26:00 — 3 minutes**

Describe the learning progression in three stages:

- Understand the architecture and reproduce attacks.
- Implement and investigate defensive controls.
- Verify repairs and explain what the evidence establishes.

Mention the course's 11 modules and 9 labs. Show a short screen capture of the
course outline or the containment notebook if useful. Use a prepared view instead
of browsing directories during the recording.

Explain the working style: Python exercises, experiments, review questions, and
concrete outputs. The full labs give students time to change controls, test
variants, and discuss gaps that a ten-minute demonstration cannot cover.

Some full-course labs use model APIs; these promotional demos do not. Avoid
implying that the entire course runs without model access or dependency setup.

## Slide 11 — Leave with Evidence You Can Explain

**26:00–28:00 — 2 minutes**

Focus on student deliverables: a defense architecture, an incident record, a
tested repair, and a review of the assistant's permissions.

Explain the expected background: security experience, HTTP/API concepts, and
basic Python. Speak directly to AppSec, SOC, API, platform, and network-security
professionals. Acknowledge that participants may specialize in different layers.

Recap three takeaways:

1. A valid credential does not authorize every action.
2. Independent boundaries must hold when the model makes a wrong decision.
3. Verify the completed effect, including after stopping and revoking access.

## Slide 12 — Build Defenses You Can Test

**28:00–30:00 — 2 minutes**

Suggested close:

“In Practical AI Security for Security Teams, we build and test these controls
ourselves—from prompt injection and RAG to agent permissions, detection, and
verified fixes. If you want to bring that practice to your team, use the course
contact link in the description to ask about dates or a team workshop.”

Give viewers a moment to read the course name and action. End cleanly; do not
introduce another technical topic. If you finish early, keep the conclusion short
rather than stretching it to exactly thirty minutes.

## Sources and Attribution

- OpenAI, *Agent security in the enterprise*, August 2026, printed pp. 4–5,
  13–20, and 24–27. [Download page](https://openai.com/business/learn/agent-security-enterprise/).
- [Designing agents to resist prompt injection](https://openai.com/index/designing-agents-to-resist-prompt-injection/).
- Course implementation: [Lab 08 containment](../labs/08-Layered-Defense/containment/lab-08-containment.md)
  and [Lab 09 verified fixes](../labs/09-Verified-Fixes/lab-09-verified-fixes.md).

The demo uses the course's synthetic fixture. It demonstrates selected control
behavior, not a guarantee about a vendor, model, or production deployment.
