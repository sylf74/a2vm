# Pillar 3 — Triage & Prioritization

Part of the high-level design (HLD). Goals, constraints, contracts between pillars and the AI
strategy are in [00-product-strategy.md](00-product-strategy.md); this chapter only details
pillar 3.

| Item | Value |
| --- | --- |
| Package and command | `verdict` (modules `verdict.assets` and the decision) |
| Status | In development (v0.11.2) |
| LLD | [../lld/triage-prioritization.md](../lld/triage-prioritization.md) |

## 1. Responsibility

Pillar 3 holds the asset context and takes the only decision of the platform.

| Pillar 3 does | Pillar 3 does not |
| --- | --- |
| Consolidate observations into one inventory per tenant, each attribute with its source | Collect observations (pillar 2) or vulnerability records (pillar 1) |
| Reconcile declared and observed assets, internal and external | Dispatch actions or follow remediation (pillar 4) |
| Take one SSVC decision per finding (ACT, ATTEND or TRACK) with its BOD 26-04 timeline, reasons, review flags and rationale | Let AI decide (strategy D11) |
| Apply accepted risks | Send anything to the client without analyst validation |

## 2. Inputs and outputs

| Direction | What | Contract |
| --- | --- | --- |
| In | Vulnerability records | Strategy §6 |
| In | Asset observations and findings | Strategy §6 |
| In | Tenant context: declarations, rules, `published` mapping, policy, exceptions | Strategy §7 |
| Out | Assets (read only for pillars 1, 4, 5) | Strategy §6 |
| Out | Decisions; reports, `triage.json`, `triage.csv`, run page | Strategy §6 |
| Out | Reporting dataset `reporting.json`, read by the client portal (Grafana) | Strategy §6; LLD §12 |

## 3. Building blocks

| Block | Responsibility | Reads → writes |
| --- | --- | --- |
| Asset context (`verdict assets build`) | Consolidates observations into one inventory per tenant and sets each attribute with its source (exposure as SSVC value, zone, mission, well-being, owner); reconciles declared and observed assets, internal and external | Detections → `assets.json`, `findings.json` |
| Decision (`verdict run`) | One SSVC decision per finding, BOD 26-04 timeline, reasons, review flags, rationale; risk acceptance | Records, assets, findings → `triage.json`, `triage.csv`, report, run page |

## 4. Asset context

| What is known per asset | Values |
| --- | --- |
| Exposure | SSVC System Exposure: open, controlled, small |
| Mission and well-being impact | SSVC values |
| Zone | Free label (dmz, lan, ot…), for reports only |
| Owner | Team or contact in charge |

Every asset attribute carries where it comes from, in this order of precedence:

1. **Declared** by the client: profile, asset declarations, a CMDB export when available.
2. **Rule** set in the tenant project, e.g. an address range giving a zone and an exposure.
3. **Observed** by a scanner; the external scan can only raise an asset's exposure, never lower it.
4. **Assumed** when nothing else is known: a cautious default, shown as such in every report.

Assets are new, active or removed; an asset unknown to the client's inventory is created with
default context and reported; one absent from every source for a set number of days is removed. A
client CMDB, when available, is the reference for context.

## 5. Flows

1. Asset context consolidates the observations, pulls the external report and reconciles it through the `published` section (public endpoint → internal asset).
2. Decision takes each finding with its asset's exposure and mission, and the CVE's exploitation, automatability and technical impact from the evidence (AI only proposes a missing value, flagged for review); the CISA Coordinator tree, the BOD 26-04 timelines and the policy then give ACT, ATTEND or TRACK with a rationale.
3. Results are published as reports, client bulletins and dashboard data; analysts validate before delivery.

## 6. AI use cases

| Use case | What the LLM does | Safeguard and fallback | Status |
| --- | --- | --- | --- |
| Missing SSVC inputs | Proposes Automatable and Technical Impact for a fresh CVE that has neither CISA ADP data nor a CVSS vector | Source "estimated by LLM", always flagged for review; without LLM, the value is assumed and flagged | In development |
| Rationale | Writes in French the explanation of a decision already computed | Output guard: any version, score or CVE id absent from the facts rejects the text; template otherwise | In development |

## 7. Pillar decisions and principles

| Principle | Content |
| --- | --- |
| Policy as code | The decision policy is versioned, changed by merge request with a second reviewer, its combinations leading to ACT tested in CI; each decision carries the policy version, and a new version comes with a report of the priorities it changes |
| Risk acceptance | An accepted risk has a justification, an approver and an expiry date, kept in the tenant project and changed by merge request; at expiry the finding comes back |
| Determinism | Same records, assets, findings and policy version give the same decisions |
| Reporting contract | Pillar 3 publishes one reporting dataset per tenant and run (`reporting.json`, versioned schema); the client portal reads it and nothing else, so internal changes never break the portal |

## 8. Status, risks and open points

| Item | Content |
| --- | --- |
| In place | v0.9.0: SSVC decision with BOD 26-04 timelines, exposure model with source and zone; v0.11.2: external detection pulled by the tenant project and joined through `published` endpoints (exposure `open`, source `external-scan`) |
| Planned | v0.11.3: reporting dataset for the client portal; v0.11.4: exposure gap |
| Risks | Incomplete asset data from clients (safe defaults when criticality or exposure is unknown); AI proposes a wrong decision point (flagged, analyst validation) |
| Open points | Exposure gap: immediate alert through the watch (pillar 1), or a section of the daily report |
