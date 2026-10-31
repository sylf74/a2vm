# Pillar 4 — Dispatch & Capitalization

Part of the high-level design (HLD). Goals, constraints, contracts between pillars and the AI
strategy are in [00-product-strategy.md](00-product-strategy.md); this chapter only details
pillar 4.

| Item | Value |
| --- | --- |
| Package and command | — |
| Status | Not started |
| LLD | — |

## 1. Responsibility

| Pillar 4 does | Pillar 4 does not |
| --- | --- |
| Dispatch the decisions to the clients and the teams that remediate, as actions: patches, mitigations, workarounds, tickets, notifications | Change a decision or the asset context (pillar 3) |
| Follow each finding to verified closure | Close a finding without a new observation confirming the absence |
| Capitalise: finding history, lessons, indicators | Restitute the decisions: the reporting database and its dashboards belong to pillar 3 (`verdict.restitution`, since v0.11.6) |

## 2. Inputs and outputs

| Direction | What | Contract |
| --- | --- | --- |
| In | Decisions | Strategy §6 |
| In | Assets (read only): owner, exposure | Strategy §6, §7 |
| Out | Actions, finding lifecycle, indicators | To define in this chapter |

## 3. Building blocks

| Block | Responsibility | Status |
| --- | --- | --- |
| Dispatch channels | Where a validated alert, and later an ACT decision, goes for a tenant and for each of its contacts: mail (the sender of the review page today), or an ITSM tool through a connector | Planned v0.19.0 |
| ITSM connectors | One interface (create, update, read the state of a ticket), one connector per tool: TheHive first (case or alert, API v1), ServiceNow (incident or security incident, REST Table API), others later; the ticket's reference and state kept with the alert; credentials in the tenant's secrets, never in its project files; the tool reached only from the tenant's namespace, by its NetworkPolicy | Planned v0.19.0 |

The channels are configured with the contacts (`contacts.yaml`: a contact is a mailbox or a
queue of an ITSM tool) so that the analyst still chooses the recipients on the review page, and
the language of each recipient still applies (D16). A connector proposes nothing and decides
nothing: it carries what an analyst validated.

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
| Status | Not started. v0.11.5 had put the reporting database in a package named `dispatch`; v0.11.6 moved it to pillar 3, which restitutes its own decisions, and removed the package: the name stays for this pillar |
| Open points | Dispatch channels per client: mail and ITSM connectors (TheHive, ServiceNow) planned in v0.19.0 (§3), their mapping of fields and severities to settle with each tool; finding lifecycle with the history database; indicators of remediation (time to fix, reopened findings) |
