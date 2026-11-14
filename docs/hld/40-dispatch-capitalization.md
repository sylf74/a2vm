# Pillar 4 — Dispatch & Capitalization

Part of the high-level design (HLD). Goals, constraints, contracts between pillars and the AI
strategy are in [00-product-strategy.md](00-product-strategy.md); this chapter only details
pillar 4.

| Item | Value |
| --- | --- |
| Package and command | `dispatch` (since v0.20.0) |
| Status | In development: remediation tickets in iTop, requests for remediation from the dashboards (v0.20.0) |
| LLD | [`../lld/dispatch-capitalization.md`](../lld/dispatch-capitalization.md) |

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
| In | Rules of the tenant: targets, what leaves by itself, what a person may ask | `dispatch.yaml`, `dispatch.schema.json` (v0.20.0) |
| Out | Tickets in the ITSM, their state; requests of the persons | Dispatch service, `dispatch.v1.yaml` (v0.20.0) |

## 3. Building blocks

| Block | Responsibility | Status |
| --- | --- | --- |
| Dispatch channels | Where a validated alert or a decision goes for a tenant and for each of its contacts: mail (the sender of the review page today), the ITSM of the teams that patch, the SOC's incident response platform (SIRP); rules per tenant of what goes where (`dispatch.yaml`: automatic tickets none, ACT or ACT and ATTEND; zones left out; what a person may ask) | ITSM in place (v0.20.0); SIRP planned |
| ITSM connectors | Remediation: one ticket per asset and fix (iTop first: UserRequest through its REST API, linked to the CMDB item when known; ServiceNow next: REST Table API), with its CVEs, levels and BOD 26-04 due date. The ticket follows the finding: closing it does not close the finding, only a new scan of the asset does (LLD triage §15.8); NGVM writes the fixes a scan confirmed, resolves the ticket when none is left and reopens it when it was closed too early | iTop in place (v0.20.0); ServiceNow planned |
| Requests for remediation (D18) | A person of a remediators' group follows a link "Remediate" of an RSSI dashboard to a page of the dispatch service, which shows the tickets of the selection and sends them on confirmation, recorded with who asked | In place (v0.20.0) |
| SIRP connectors | Suspected compromise only (BOD 26-04 delay "3 days & forensic investigation", or a watch alert on an exploitation in the wild of an exposed asset): an alert in TheHive (API v1) with its observables (CVE, host names, addresses), which the SOC promotes to a case. Never a channel for remediation, never a step towards the ITSM: the two flows leave NGVM side by side | Planned (after v0.20.0) |
| Connector interface | Create, comment, resolve, reopen, read the state; the external reference and state kept with the ticket; credentials in the tenant's secrets, never in its project files; each tool reached only from the tenant's namespace, by its NetworkPolicy | In place (v0.20.0) |

The channels are configured with the contacts (`contacts.yaml`: a contact is a mailbox, a
queue of an ITSM tool or of the SIRP) so that the analyst still chooses the recipients on the review page, and
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
| Status | In development since v0.20.0. v0.11.5 had put the reporting database in a package named `dispatch`; v0.11.6 moved it to pillar 3, which restitutes its own decisions, and removed the package: the name stays for this pillar |
| Open points | ServiceNow and the SIRP (TheHive), their mapping of fields and severities to settle with each tool; the tickets in the reporting database and the dashboards; several targets for automatic tickets (per zone, per owner) |
