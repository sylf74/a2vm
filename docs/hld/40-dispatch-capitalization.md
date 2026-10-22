# Pillar 4 — Dispatch & Capitalization

Part of the high-level design (HLD). Goals, constraints, contracts between pillars and the AI
strategy are in [00-product-strategy.md](00-product-strategy.md); this chapter only details
pillar 4.

| Item | Value |
| --- | --- |
| Package and command | — |
| Status | In development: the reporting database (v0.11.5) |
| LLD | — |

## 1. Responsibility

| Pillar 4 does | Pillar 4 does not |
| --- | --- |
| Turn decisions into actions for the teams that remediate: patches, mitigations, workarounds, tickets | Change a decision or the asset context (pillar 3) |
| Follow each finding to verified closure | Close a finding without a new observation confirming the absence |
| Capitalise: finding history, lessons, indicators | |

## 2. Inputs and outputs

| Direction | What | Contract |
| --- | --- | --- |
| In | Decisions | Strategy §6 |
| In | Assets (read only): owner, exposure | Strategy §6, §7 |
| Out | Actions, finding lifecycle, indicators | To define in this chapter |

## 3. Building blocks

To define.

## 4. Flows

Nominal flow, after pillar 3: ACT items are turned into remediation actions and followed to
verified closure.

## 5. AI use cases

| Use case | Status |
| --- | --- |
| Ideas: drafts of remediation instructions or tickets, capitalisation summaries | Not started |

## 6. Pillar decisions and principles

| Principle | Content |
| --- | --- |
| Decision history | A finding keeps a stable identity (asset, CVE, component) and a lifecycle: open, reclassified, remediation claimed, remediation verified, reopened, risk accepted. Only a new observation confirming the absence closes it; an exit from ACT without verified remediation is a security event. Built with the history database |

## 7. Status, risks and open points

| Item | Content |
| --- | --- |
| Status | In place: the reporting database (package `dispatch`, v0.11.5): every run's reporting dataset kept in PostgreSQL with a reading role per tenant, read by the Grafana dashboard (`docs/reporting.md`). Not started: ticketing, finding lifecycle |
| Open points | Ticketing integration; Qlik Sense connection (interface specifications pending); indicators beyond the dashboard |
