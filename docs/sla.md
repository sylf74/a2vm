# Priorities and SLA of a client (v0.21.0)

The BOD 26-04 timelines are the default SLA of every client: ACT and ATTEND findings are due a number
of days after their first observation (3, 14 or 60 days, or at the next major upgrade). A client may
commit to its own priorities and their delays: stricter for its exposed or critical assets, counted in
business days, a short delay for every known exploited vulnerability. They are set in its profile and
applied by verdict to every decision, run after run (HLD D19; design: LLD triage-prioritization §17).

The level does not change: ACT, ATTEND and TRACK stay the SSVC decision and the policy. The client's
rules only sort the decisions into its priorities. Everything is deterministic: no LLM, the rule
applied is recorded on each decision, and the BOD 26-04 due date is kept beside the client's for
comparison.

## 1. The section `sla` of `client.yaml`

```yaml
sla:
  calendar: business
  holidays: FR
  timezone: Europe/Paris
  rules:
    - {priority: P0, days: 2, calendar: calendar, when: {kev: true}}
    - {priority: P1, days: 5,  when: {level: ACT, exposure: open}}
    - {priority: P2, days: 10, when: {level: ACT, exposure: controlled}}
    - {priority: P3, days: 15, when: {level: ACT}}
    - {priority: P4, days: 30, when: {level: ATTEND, exposure: open}}
    - {priority: P5, days: 90, when: {level: ATTEND}}
```

| Key | Content | Default |
| --- | --- | --- |
| `calendar` | `calendar`: every day counts (24/7, follow the sun); `business`: Monday to Friday, less the public holidays | `calendar` |
| `holidays` | Public holidays left out of business days: `FR` (the eleven of metropolitan France, Easter Monday, Ascension and Whit Monday included) | none |
| `extra_holidays` | Other days left out of business days (a closure, a local holiday), `YYYY-MM-DD` | none |
| `timezone` | IANA time zone of the client's days (`Europe/Paris`): a run at 23:30 UTC is on the next day in Paris | `UTC` |
| `rules` | The priorities, most urgent first; the first rule that matches a decision applies | — |

A rule has a `priority` (a free name: `P0`..`Pn`, `Q0`...), `days` (0 or more, counted in its
calendar) and `when` (its criteria); it may override `calendar`, `holidays` and `extra_holidays`. A
rule without `when` takes every decision, so it can close the list.

| Criterion | Values | Holds when |
| --- | --- | --- |
| `level` | `ACT`, `ATTEND`, `TRACK`, or a list | The decision's level is one of them |
| `kev` | `true`, `false` | The CVE is (not) in CISA KEV. `{kev: true}` alone covers every KEV, whatever its level |
| `exposure` | `open`, `controlled`, `small`, or a list | The asset's exposure is one of them |
| `zone` | A zone of the profile, or a list | The asset's zone is one of them |
| `epss`, `cvss` | A number (at least), or `{min: 0.1, max: 0.5}` (both included) | The score is in range; an unknown score never holds |
| `cmdb` | Fields of the asset's CMDB item, each one value or a list: `criticality`, `class`, `status`, `organization`, `type` | Every field is one of its values (without case); an asset without a CMDB item never holds |

Every criterion of a rule must hold. Examples:

```yaml
    - {priority: P1, days: 3, when: {level: ACT, cmdb: {criticality: [high, critical], status: production}}}
    - {priority: P2, days: 5, when: {level: [ACT, ATTEND], epss: 0.5}}
    - {priority: Q9, days: 120}
```

A decision that no rule matches has no priority: its BOD 26-04 due date stays its only one, and it is
not counted in the respect of the SLA. Without the section, nothing changes: BOD 26-04 only.

The job `validate` checks the section (schema, time zone, public holidays, criteria): a mistake
stops the pipeline before any run.

## 2. When a delay starts

A delay starts on the day verdict puts the decision into its priority: the day of the run that
publishes it to the portal and to the ITSM, in the client's time zone. That day counts as day 0; in
business days, a start on a Friday with 3 days is due on the Wednesday after (on the Thursday when
that Wednesday is a public holiday, as 11 November). After that:

- **same priority** on the next runs: the same start, the same due date;
- **a priority that goes up**: a new delay from the change, never beyond the due date already set;
- **a priority that goes down**: the due date already announced is kept;
- **leaving every priority** (e.g. the decision becomes TRACK) ends the obligation; coming back is a
  new entry, as is a finding fixed then seen again.

A due date announced is never moved later while the decision stays in a priority: a delay
lengthened in the profile applies to the decisions that enter the priority afterwards, a delay
shortened applies at once.

The start is known from the history of the tenant's database (v0.18.0): on Kubernetes with
`A2VM_DATABASE=true`, the daily run reads it from the decision service before the triage. Each
decision says where its start comes from (`since_source`):

| `since_source` | Start |
| --- | --- |
| `run` | The day of this run: the decision enters its priority now |
| `history` | The day it entered its priority, kept in the database |
| `level_since` | The day it got its level: a decision known before the client's SLA (the upgrade to v0.21.0, or a section added later) |
| `first_seen` | Its first observation: no history known (GitLab pipeline mode, or the decision service not reached that day, a warning in the job log and the report) |

A run that did not know the history never replaces, in the database, what it knows of a priority
that did not change: the next run starts from it again.

## 3. Where the priority shows

| Where | What |
| --- | --- |
| `triage.json` | `sla` of each decision: priority, rule, days, calendar, start and its source, due date, BOD 26-04 due date; the policy in force for the run |
| `triage.csv` | Columns `priority`, `sla_due`, `bod_due` |
| Daily report, run page | Section "Priorities and SLA": per priority the open decisions, those past their due date, those due within 7 days; a column priority and earliest SLA due date in the ACT and ATTEND tables |
| Chat | "Which P1 are overdue?", "what is due this week for the client's SLA?": filters `priority`, `sla_overdue`, `sla_due_before`, sorts `priority`, `sla_due`; the summary lists the priorities; the CSV export has the priority and the SLA due date, the Word and PowerPoint explanation the rule applied |
| Reporting database (schema 5) | `decisions`: `priority`, `sla_due`, `sla_since`, `sla_rule`; `decision_facts`: `sla_status` (`overdue`, `on-track`) and `deadline`; `finding_closures`: `within_sla`; `runs`: `sla_overdue`, `sla_due_soon` (`docs/reporting.md`) |
| Grafana | Dashboard `sla` (priorities and SLA): open with a priority, past their SLA due date, due within 7 days, share fixed within the SLA beside the same findings against BOD 26-04, per priority, overdue per day, overdue decisions; the dashboard `remediation` shows the priority of the findings fixed |
| Tickets (iTop) | Title `[A2VM ACT P1] …`; text with the priority, the SLA due date and the BOD one; the ticket's due date is the earliest SLA due date of its findings; impact and urgency per priority when `dispatch.yaml` maps them (`docs/dispatch.md`) |

## 4. Upgrading a tenant to v0.21.0

1. Move `ref` and `A2VM_REF` to `v0.21.0` and push.
2. On each reporting database, `verdict db init` once (schema 5, `docs/reporting.md`); a portal on
   Kubernetes does it at its upgrade.
3. Import the dashboard `sla` (and `--language fr`, `--rssi`) on a portal set up by hand; a portal on
   Kubernetes provisions it.
4. When the client has an SLA: add the section `sla` to `client.yaml` (merge request). The decisions
   already open start from the day they got their level; the new ones from the day they enter their
   priority.
