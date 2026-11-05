# Dispatch & Capitalization — low-level design

| Item | Value |
| --- | --- |
| Building block | Pillar 4 package `dispatch` (command `dispatch`): rules of the tenant (`dispatch.rules`), tickets (`dispatch.tickets`), what happens after a run and on a request (`dispatch.engine`), connectors (`dispatch.connectors`: iTop), dispatch service and page of the requests for remediation (`dispatch serve`) |
| Status | v0.20.0 as built: remediation tickets in iTop. The SIRP (TheHive) and ServiceNow come later |
| Place in the set | C4 level 3 of pillar 4 of the HLD ([`../hld/40-dispatch-capitalization.md`](../hld/40-dispatch-capitalization.md)). Goals, constraints and contracts: HLD (D12, D15, D18). Servers, zones and flows: DAT |
| Code | `dispatch/src/dispatch/` |

This document says how pillar 4 carries the decisions of pillar 3 to the tools of the teams that
act on them: which decisions leave, as what, to which tool, and how their state comes back. It is
updated in the same merge request as the code it describes.

## 1. Scope

Two flows will leave A2VM, each to its own team, side by side and never chained: **remediation**
tickets in the ITSM of the teams that patch (v0.20.0: iTop), and alerts in the SOC's incident
response platform on a suspected compromise (SIRP, TheHive, planned). This version builds the first.

| dispatch does | dispatch does not |
| --- | --- |
| Group the decisions of a run into tickets, one per asset and fix (§2) | Take or change a decision, a level, a due date (pillar 3) |
| Send by itself the tickets of the levels the tenant chose (none, ACT, or ACT and ATTEND, §4) | Act on a click: a link of a dashboard only opens the page (D18) |
| Create the tickets a person asks for from a dashboard, after a confirmation (§3.2) | Close a finding: only a new scan does (LLD triage §15.8); a ticket closed in the tool is a claim |
| Keep each ticket's external reference and state, and write the progress of its findings into it (§3.3) | Write in the CMDB (read only, LLD detection §3.5) |
| Record who asked what and when, and what each tool answered | Hold a credential outside the tenant's secrets |

No LLM: the title and the text of a ticket come from templates, the facts from the decisions (D11).

### 1.1 Interfaces with the other pillars

| Way | Interface | Kind | Contract | Other side | Access | When the other side is missing |
| --- | --- | --- | --- | --- | --- | --- |
| Provides | Dispatch service (`dispatch serve`, §6) | API | `dispatch.v1.yaml` | Daily run (step `dispatch`, role `run`); tools (role `read`) | Run and read tokens | The daily run warns; the next run dispatches |
| Provides | Page of the requests for remediation (§3.2) | Web page behind oauth2-proxy | — | Persons of the groups `A2VM_OIDC_REMEDIATORS`, from the links of the RSSI dashboards (D18) | OIDC sign-in | — |
| Consumes | Decision service | API | `verdict.v1.yaml` (`GET runs`, `decisions` with their `fixes` and, since v0.21.0, `priority`, `priority_rank`, `sla_due`, `assets/{asset}`, `findings/closed`) | verdict (`verdict serve`) | Read token | Nothing dispatched, the step warns (exit 3) |
| Consumes | Rules of the tenant (`dispatch.yaml`, §4) | Exchange file (tenant project) | `dispatch.schema.json` | Tenant project | ConfigMap | Without the file the service is not deployed |

## 2. Ticket

A ticket is the unit sent to the ITSM: **one asset and one fix**, with the decisions that fix
clears. Its key is stable from run to run: `<asset id> / <fix>`, e.g.
`host:web01.lab.example / openssl 3.0.15-1`.

The fix is one of the fixes the scanners reported for the decision (`<package> <fixed version>`,
`fixes` of the decision items of `verdict.v1` since v0.20.0). A decision goes to one ticket only:
among the fixes of its asset, the one that clears the most ACT, then ATTEND, then KEV, then by
name. The decisions of an asset without a known fix make one ticket `<asset> / no known fix`
(mitigation or acceptance, for the team to decide).

| Field | Content |
| --- | --- |
| `key`, `asset`, `asset_name`, `fix`, `zone` | Identity |
| `findings` | The decisions it covers by finding id, each with its CVE, level, KEV, EPSS, CVSS, due date, product and state: `open`, `unverified` (absent from the newest run, its asset not scanned again), `fixed` (closed by a scan, with the day); since v0.21.0 its priority in the client's SLA (`priority`, `priority_rank`) and `bod_due`; its `due` is its SLA due date when it has a priority, else the BOD 26-04 one |
| `level`, `priority`, `due` | Highest level, most urgent priority of the client's SLA (v0.21.0, HLD D19; "" without one) and earliest due date of its open findings |
| `cmdb` | Class and key of the CMDB item of the asset (v0.19.0), read from the asset's card when the ticket is created: the ticket is linked to it |
| `origin`, `requested_by`, `requested_at`, `comment` | `rule` (§3.1) or `request` (§3.2): who asked, when, their comment |
| `target`, `external` | The target of `dispatch.yaml`; the tool's reference, URL and status |
| `state`, `error`, `history` | A2VM's state; the last refusal of the tool; the last 100 events |

States:

```
proposed ──► sent ──► in-progress ──► fixed (every finding closed by a scan)
   ▲            │            ▲
   │            └──► claimed-fixed (closed in the tool, a finding still seen) ──► in-progress (reopened)
   └── dry-run, or refused by the tool (tried again at the next run)       lost (the tool no longer knows it)
```

A ticket `fixed` or `lost` whose key comes back with new findings is sent again as a new ticket in
the tool, its history kept.

Title: `[A2VM <level>] <asset name>: apply <fix> (<n> CVEs)`, `[A2VM <level> <priority>] …` when a
finding has a priority (v0.21.0). Text (HTML): asset, fix, level, due date (with a priority: the
priority, the SLA due date and, for comparison, the BOD 26-04 one), that closing the ticket does not
close the vulnerabilities, the requester and comment, and a table of the CVEs (level, priority, KEV,
EPSS, CVSS, due date, product, state).

## 3. Flows

### 3.1 After each run

With the service deployed, the daily run ends with a step `dispatch` after `publish` (the last
container of the CronJob; the lock of the working volume is released there): `dispatch run` asks
the service to process the newest run of the decision service (`POST /v1/tenants/{tenant}/runs`).

1. **Automatic tickets**: the decisions of the levels of `tickets.automatic`, out of
   `exclude_zones`, grouped into tickets. A new key is sent; a known key gets the findings it did
   not have, with a comment in the tool listing them; the levels and due dates of its findings are
   updated.
2. **Follow-up** of every open ticket (§3.3), automatic or asked by a person.
3. The step prints the summary (proposed, sent, updated, fixed, claimed fixed, reopened, errors)
   and exits 3 (a warning) on an error: the next run tries again.

Processing a run twice changes nothing (keys, findings by id). One run or request at a time per
tenant (a lock in the service, one replica).

### 3.2 Request by a person (D18)

The RSSI versions of the dashboards `remediation` and `coverage` carry, on the column Asset, a link
"Ask for the remediation of this asset", and in their header a link "Ask for the remediation of
every ACT":

```
https://dispatch-<tenant>.<domain>/remediate?asset=web01.lab.example
https://dispatch-<tenant>.<domain>/remediate?level=ACT
```

Filters accepted: `asset`, `cve`, `level`, `zone`, `exposure`, `kev`, `product`, `q`, `overdue`,
and since v0.21.0 `priority`, `sla_overdue` (those of `GET decisions`; the RSSI version of the
dashboard `sla` links its overdue decisions by asset); `level` is cut to the levels of `requests.levels`.

1. oauth2-proxy signs the person in and lets in the members of the remediators' groups only; the
   page checks the groups again and shows nothing before (401, 403).
2. `GET` shows the tickets of the selection on the newest run, by the grouping of §2, each marked
   new, proposed, already sent (with its reference) or in progress; nothing is written. At most
   `requests.max_tickets` (default 50); beyond, the page asks to narrow the selection.
3. The person unticks what they do not want, chooses the target among `requests.targets`, adds a
   comment for the team, and confirms.
4. `POST`: the form must come from the page's origin and carry its token (HMAC of the person, the
   selection and the run, key `dispatch-page-key`). When a newer run arrived in between, nothing
   is sent and the page shows the selection again. Otherwise the chosen tickets are created, or
   updated when their key is already sent (never a duplicate), with `origin: request`, the
   person's e-mail and the comment; the request is recorded (who, when, selection, run, tickets).

The page answers in English (D16), with `Cache-Control: no-store`, no framing, and a content
security policy that allows no script.

### 3.3 Follow-up

For each open ticket, against the newest run and the findings closed since the ticket was created
(`GET findings/closed`, with the tenant's database):

| Finding | Becomes |
| --- | --- |
| In the newest run | `open`, its level, priority and due date updated |
| Closed by a scan | `fixed`, with the day; a comment in the tool lists the CVEs fixed |
| Absent, not closed | `unverified`: not a fix (the asset was not scanned again) |

When no finding is open, the ticket is `fixed`, and resolved in the tool (`resolve_when_fixed`,
default true) unless it already is. Otherwise A2VM reads the tool's status: closed there while a
finding is still seen → `claimed-fixed`, a comment names what the last scan still sees, and the
ticket is reopened in the tool (`reopen_when_still_seen`, default true); unknown to the tool →
`lost`. A2VM never takes the tool's word for a fix.

## 4. Rules of the tenant (`dispatch.yaml`)

In the tenant project, next to `contacts.yaml`, checked against `dispatch.schema.json` by the job
`validate` (`dispatch check`), mounted from the ConfigMap. No credential in it.

```yaml
schema_version: 1
mode: dry-run              # dry-run (default): proposed and recorded, nothing sent; live: sent
targets:
  itsm:
    type: itop
    url: https://itop.lab.example
    user: a2vm-itsm        # its password: CI/CD variable A2VM_DISPATCH_ITSM_PASSWORD
    organization: Lab
    caller: A2VM           # the iTop Person the tickets come from
    team: Linux            # optional: the iTop Team they are given to
    priorities:            # optional (v0.21.0): priority of the client's SLA -> impact, urgency
      P0: {impact: 1, urgency: 1}
      P1: {impact: 2, urgency: 1}
tickets:
  target: itsm
  automatic: act           # none | act (default) | act-attend
  exclude_zones: [lab]
  resolve_when_fixed: true
  reopen_when_still_seen: true
requests:
  targets: [itsm]
  levels: [ACT, ATTEND, TRACK]
  max_tickets: 50
```

Without `tickets`, nothing leaves by itself; without `requests`, the page says the tenant has no
target for requests. In dry-run, the tickets stay `proposed` (the page's button says "Record the
request (dry run)"); the first run in live mode sends them.

## 5. Connectors

A connector maps a ticket to one tool and back, and nothing else: `create`, `comment`, `resolve`,
`reopen`, `status` (the tool's status and A2VM's reading of it: working, closed, gone). A refusal is
kept on the ticket (`error`) and in the log; the ticket is tried again at the next run. The
credential of a target `<name>` is the key `dispatch-<name>` of the tenant's Secret, the CA of its
certificate, when private, `dispatch-<name>-ca`.

### 5.1 iTop

REST API 1.3, a local account of its own (`a2vm-itsm`), distinct from the read-only CMDB account of
pillar 2, allowed to create and update user requests in the tenant's organisation.

| A2VM | iTop (`UserRequest`) |
| --- | --- |
| create | `core/create`: `org_id` (`organization`), `caller_id` (Person `caller`), `team_id` (`team`), `title`, `description` (HTML), `impact` and `urgency` from the priority of the client's SLA when `priorities` maps it (v0.21.0), else from the level (ACT 2/1, ATTEND 3/2, TRACK 3/3); a ticket already created keeps them, `functionalcis_list` (the CMDB item) |
| comment | `core/update`: an entry in `public_log` |
| resolve | `core/apply_stimulus` `ev_resolve`, `solution`, `resolution_code` "software patch" |
| reopen | `core/apply_stimulus` `ev_reopen`, then a comment |
| status | `core/get`: resolved, closed, rejected → closed; any other → working; no object → gone |

### 5.2 Planned

ServiceNow (Table API), TheHive (alerts on a suspected compromise: BOD delay "3 days & forensic
investigation", then the watch's alerts on an exploitation in the wild, with D17).

## 6. Dispatch service (`dispatch serve`)

| Item | Value |
| --- | --- |
| API | `/v1/tenants/{tenant}/runs` (POST, role `run`), `tickets`, `tickets/{id}`, `requests` (GET, role `read`); contract `a2vm/src/a2vm/schemas/openapi/dispatch.v1.yaml` |
| Page | `/remediate` (GET, POST) on port 8081, behind oauth2-proxy (`<release>-<tenant>-dispatch-page`), as the review page of the alerts (`docs/sign-in.md`); only the proxy reaches the port |
| Storage | The tenant's PostgreSQL, schema `dispatch` (`tickets`: key, state, target, asset, reference, document; `requests`), row-level security on the tenant; without it, files on the volume of the service |
| Secrets | Mounted item by item: `verdict-read-token`, `dispatch-page-key`, and `dispatch-<target>` (`-ca`) of each target of `dispatch.yaml`; never the tenant's other secrets; read from files, never logged |
| Network | In: the daily run and the pods labelled `a2vm.io/dispatch-reader=true` (8080), the page's proxy (8081). Out: the decision service, the targets (`dispatch.egress`, resolved by `deploy-k8s`), the tenant's database, the DNS |
| Deployment | One replica (`Recreate`); deployed by `deploy-k8s` when the tenant project has `dispatch.yaml` and the decision service runs |

## 7. Restitution

The dashboards `remediation` and `coverage` have an RSSI version (`verdict grafana dashboard NAME
--rssi`, files `*.rssi.json` and `*.rssi.fr.json`): the same, with the links of §3.2, its own uid
(`-rssi`) and a constant `dispatch_url` asked at import. It is imported in a folder for the persons
who may ask for remediation; the reading version stays where it is. The tickets in the reporting
database (a column per decision) are planned.

## 8. Failure modes

| Case | Behaviour |
| --- | --- |
| Decision service unreachable | `POST runs` answers 502, the step warns (exit 3), nothing changes |
| A target unreachable or refusing | The ticket stays `proposed` with the error, the others go on, the step warns; next run |
| A newer run between the page and the confirmation | Nothing sent, the selection shown again |
| The same key asked twice | The second updates the ticket the first created |
| Ticket deleted in the tool | `lost`; sent again only if wanted again |
| `mode: dry-run` | Nothing reaches a tool; the step and the page say so |

## 9. Tests

`tests/test_v0200.py`: rules and their schema; grouping and keys; automatic tickets, dry-run then
live, new findings, fixed only on a scan's confirmation and resolved, claimed fixed and reopened,
refusal retried; requests (nothing written on GET, who recorded, no duplicate, newer run, levels
and cap); page (sign-in, group, origin, token); service roles; iTop connector against recorded
answers; the tickets in PostgreSQL (row-level security); RSSI dashboards; chart, pipeline and
values of `deploy-k8s`. `tests/test_architecture.py`: no import of another pillar.

## 10. Open points

- The tickets in the reporting database and the dashboards (a column per decision).
- ServiceNow; TheHive (§5.2).
- Several targets for automatic tickets (per zone, per owner or CMDB organisation).
