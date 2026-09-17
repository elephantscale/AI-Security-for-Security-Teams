# 30-Minute Course Preview — When the AI Gets Fooled

A recording package for **Practical AI Security for Security Teams**.
The audience is AppSec, SOC, API, platform, and network-security professionals.

## Recording Materials

- [Slides](../slides/promo-slides.md): 12 slides, separated by `---`, ready for Markdown-to-PowerPoint conversion.
- [Presenter notes](presenter-notes.md): timing, talking points, transitions, and attribution.
- [Demo labs](labs/README.md): three short demonstrations with commands and expected results.
- [Demo notebook](labs/demo.ipynb): one executable cell per demonstration.
- [Demo runner](labs/demo.py): standard-library Python; no API key or package installation required.

The preview source is `slides/promo-slides.md`, included at the end of
`slides/slide-list.txt`. Run `./gen.sh` from `slides/` to build all decks, including
`slides/assembly.out/12__promo-slides.pptx` for this recording.

## Running Order

| Slide | Segment | Time |
|---|---|---|
| 1 | Introduction | 00:00–01:00 |
| 2 | Poisoned support ticket | 01:00–03:00 |
| 3 | Why agent actions change the problem | 03:00–05:00 |
| 4 | Identify the enforcement boundary | 05:00–07:00 |
| 5 | Demo 1: unprotected effect | 07:00–09:00 |
| 6 | Demo 2: containment and legitimate work | 09:00–14:00 |
| 7 | Demo 3: stop and revoke | 14:00–17:00 |
| 8 | Explain the architecture | 17:00–20:00 |
| 9 | Apply the questions across AI systems | 20:00–23:00 |
| 10 | Course learning path | 23:00–26:00 |
| 11 | Student outcomes and takeaways | 26:00–28:00 |
| 12 | Invitation | 28:00–30:00 |

## Rehearsal

From the course root:

```sh
python3 promo/labs/demo.py all
```

Every scenario creates fresh state. Repeat any take without resetting the course
labs. Use the full checkout, because the runner shares Lab 08's control fixture.
The notebook additionally requires an existing Jupyter environment.

Capture each demo separately with a large terminal or notebook font. Keep the
simulation label visible. The slides and notes identify exactly where each clip
fits. The presenter notes are an outline; rehearse the narration against the
timing rather than assuming the text itself takes thirty minutes to read.

## Publishing Copy

**Suggested video title:** When the AI Gets Fooled: How Security Teams Keep Control

**Description template:**

An AI agent can use valid credentials and still attempt an unauthorized action.
In this practical lesson, we replay a poisoned support-ticket scenario, enforce
resource boundaries, preserve legitimate work, and demonstrate why stopping an
agent and revoking its authority are different operations.

The demonstrations use synthetic data and deterministic local simulations.
They do not call a live model or send real messages.

Explore **Practical AI Security for Security Teams**: 11 modules and 9 labs covering
prompt injection, RAG, agents, API controls, detection, layered defense, and
verified security repairs.

Course details / contact: **[INSERT YOUR COURSE PAGE OR CONTACT LINK]**

Further reading: OpenAI, *Agent security in the enterprise*:
https://openai.com/business/learn/agent-security-enterprise/

**Before publishing:** Replace the description's contact placeholder with your
real destination. The final slide points viewers to that description, so no
unverified course URL or enrollment date is built into the deck.
