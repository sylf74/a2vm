# Pillar 5 — Emergency Actions

Part of the high-level design (HLD). Goals, constraints, contracts between pillars and the AI
strategy are in [00-product-strategy.md](00-product-strategy.md); this chapter only details
pillar 5.

| Item | Value |
| --- | --- |
| Package and command | — |
| Status | Not started |
| LLD | — |

## 1. Responsibility

Wartime: act outside the normal cadence when a critical vulnerability is actively exploited, across
clients.

| Pillar 5 does | Pillar 5 does not |
| --- | --- |
| Produce emergency measures and workarounds (e.g. firewall rules, isolation) | Replace the nominal decision of pillar 3 |
| Establish the impacted-client list from the asset context | Notify a client without analyst validation |
| Drive the short circuit from alert to measure to communication | |

## 2. Inputs and outputs

| Direction | What | Contract |
| --- | --- | --- |
| In | Alerts and vulnerability records (pillar 1) | Strategy §6 |
| In | Assets (read only): exposure, owner | Strategy §6, §7 |
| Out | Impacted-client list, emergency measures, notifications | To define in this chapter |

## 3. Building blocks

To define. Pillar 5 reuses pillars 1 to 3.

## 4. Flows

1. A critical, actively exploited vulnerability is flagged by Intelligence or an analyst.
2. The watch (every 10 minutes per tenant) matches CERT-FR alerts, new KEV entries and critical CVEs against each client's assets and watchlist, and drafts alert sheets (in place, pillar 1).
3. Emergency Actions produce emergency mitigations and the impacted-client list (not started).
4. Analysts validate and the client is notified; STIX objects go to OpenCTI / the SOC when relevant (planned).

## 5. AI use cases

| Use case | Status |
| --- | --- |
| Idea: drafts of crisis communications | Not started |

## 6. Pillar decisions and principles

To define.

## 7. Status, risks and open points

| Item | Content |
| --- | --- |
| Status | Not started; begins after v0.10.x |
| Open points | Trigger mechanism (manual pipeline, API call, watchlist rule) |
