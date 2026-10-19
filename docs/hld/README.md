# AI-Assisted Vulnerability Management — High-Level Design (HLD)

One HLD, in six chapters: the product strategy, then one chapter per pillar. Read the strategy
first; it is enough for a complete view of the product. A pillar chapter details its own part and
never contradicts the strategy.

| Item | Value |
| --- | --- |
| Status | Draft for review |
| Version | 0.2 |
| Product | AI-Assisted Vulnerability Management |
| Project / repository | vulnops |
| Maturity | In development |
| Out of scope | Implementation detail: see the LLDs in [`../lld/`](../lld/README.md); servers, zones and flows: the DAT of each deployment (outside the repository) |
| Licence of the software | Proprietary, all rights reserved, pending a licensing decision |

| Chapter | Content | Owner |
| --- | --- | --- |
| [00-product-strategy.md](00-product-strategy.md) | Vision and goals, value chain, constraints, system context, structuring decisions, contracts between pillars, tenant and client context, AI strategy, deployment modes, cross-cutting security, roadmap, glossary | Product manager |
| [10-vulnerability-intelligence.md](10-vulnerability-intelligence.md) | Pillar 1 (`intel`, `alert`) | Pillar 1 product owner |
| [20-vulnerability-detection.md](20-vulnerability-detection.md) | Pillar 2 (`detect`) | Pillar 2 product owner |
| [30-triage-prioritization.md](30-triage-prioritization.md) | Pillar 3 (`verdict`, `assets`) | Pillar 3 product owner |
| [40-dispatch-capitalization.md](40-dispatch-capitalization.md) | Pillar 4 | Pillar 4 product owner |
| [50-emergency-actions.md](50-emergency-actions.md) | Pillar 5 | Pillar 5 product owner |

Every pillar chapter follows the same outline: responsibility, inputs and outputs, building
blocks, flows, AI use cases, pillar decisions and principles, status, risks and open points.

## Changing the HLD

- A change to one pillar is a merge request on that pillar's chapter only, approved by its owner (`.gitlab/CODEOWNERS`).
- A change that affects several pillars (a new field in a shared object, a new constraint, a new decision) also changes `00-product-strategy.md`, and is approved by the product manager and the owners of the pillars concerned.
- A pillar chapter refers to the strategy (§ numbers) rather than repeating it.

## One document for review

`scripts/build-hld.sh` assembles the chapters in order into a single Markdown file, and into PDF or
HTML when pandoc is available, for a review outside GitLab. The assembled file is generated, never
edited.
