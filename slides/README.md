# Practical AI Security for Security Teams — Slides

Markdown sources use `---` between slides. The course introduction is in
`about.md`; Modules 1–11 are in `module1.md` through `module11.md`.

## Half-Day Workshop

[Module 11 — AI for Defense: From Findings to Verified Fixes](module11.md)
accompanies [Lab 09](../labs/09-Verified-Fixes/lab-09-verified-fixes.md).
Schedule 3.5–4 hours for slides, paired exercises, discussion, and a break.

## Generate PowerPoint Decks

From this folder, run:

```sh
./gen.sh
```

The build requires `ES_HOME` pointing to the Elephant Scale shared tools, including
`utils/presentations/slides-assembler.sh` and its Python dependencies.
`slide-list.txt` controls the English deck order. The build writes numbered decks
to `assembly.out/`; reviewed teaching decks are kept in `release/`.

Deck numbers match module numbers: `00__about.pptx` through `11__module11.pptx`.
The 30-minute course preview, [promo-slides.md](promo-slides.md), follows them as
`assembly.out/12__promo-slides.pptx`. Its [presenter notes and demos](../promo/README.md)
are kept in `promo/`.

## Enterprise Agent Security

Modules 6–10 now include task authority, capability composition, resource-side
controls, shared responsibility, agent telemetry, and incident response from
OpenAI's *Agent security in the enterprise* (August 2026). Module 11 applies the
same principles to the defensive coding assistant.

The [Lab 08 containment extension](../labs/08-Layered-Defense/containment/lab-08-containment.md)
adds 75–90 minutes after the original 60–90 minute stack exercise. These are
architectural recommendations with an executable teaching simulation.
