# Reporting database and Grafana dashboards (v0.11.6)

Every daily run publishes its reporting dataset (`output/<client>/reporting.json`) into a
PostgreSQL database; Grafana, and later the company's reporting tool, read that database and
never GitLab (HLD strategy D14, D3). One row set per run is kept, so the dashboards show trends
and compare snapshots.

```
daily pipeline ── triage ── publish ──▶ PostgreSQL (schema a2vm) ◀── Grafana (one reading role)
                                 writer role                    ◀── Qlik Sense (later)
```

Restitution is part of pillar 3 (`verdict.restitution`): it publishes the decisions verdict made,
reads nothing but the reporting dataset, and computes no rule of its own. Design: LLD
triage-prioritization §13.

## Tables (schema `a2vm`, version 6)

| Table / view | Content |
| --- | --- |
| `runs` | One row per tenant and run: version, policy hash, pipeline, totals per level, assets per level, to review, assumed inputs, overdue, due within 7 days, exposure gaps |
| `decisions` | One row per decision of the run: finding, asset, zone, exposure and its source, CVE, title, level, SSVC outcome, BOD 26-04 timeline, first seen, due date, KEV, EPSS, review flag, rationale; since version 2, CVSS score and rating, fix available, vendor, product, product type, detection sources |
| `assets`, `exposure_gaps`, `sources` | Per run: assets with their counts per level; exposure gaps; detection sources and their latest observation |
| `latest_runs`, `latest_decisions`, `latest_assets`, `latest_exposure_gaps` | The latest run of each tenant and its rows |
| `decision_facts` (view, version 2) | Every decision with its run's day and the labels the dashboards filter on: severity, KEV yes/no, EPSS band, product type, sources |
| `snapshot_runs(tenants, day)` (function, version 2) | A snapshot: for each tenant, its latest run on or before the day |
| `run_pairs`, `finding_closures`, `latest_asset_scans` (views, version 3) | Each run with the one before; each finding gone, fixed or unverified; the assets of the latest run with their last scan |
| `coverage`, `coverage_facts`, `latest_coverage` (version 4) | The scan coverage of each host asset of a run against the CMDB: state, class, CMDB status, criticality, means expected and missing, scans, last scan (`docs/cmdb.md`) |
| Priorities and SLA (version 5, v0.21.0) | `decisions`: `priority`, `priority_rank`, `sla_rule`, `sla_since`, `sla_due`, `sla_since_source` (`due_date` stays the BOD 26-04 due date); `runs`: `sla_overdue`, `sla_due_soon`, `sla_unclassified`; `decision_facts`: `priority`, `sla_due`, `sla_status` (`overdue`, `on-track`), `deadline`; `finding_closures`: `priority`, `sla_due`, `within_sla` (`docs/sla.md`) |
| When a fix happened (version 6, v0.22.2) | `declared_fixes`: the date the team declared each finding fixed in the ITSM (from the dispatch service); `finding_closures`: `last_vulnerable`, `first_clean`, `declared_at`, `deadline`, `fix_status` (`met (observed)`, `met (declared, verified)`, `missed`, `to verify`, `docs/sla.md` §4) |
| `tenant_roles` | Which tenants a reading role sees (`*` = all) |

The writer role owns the tables. Reading roles get `SELECT` and see only their tenants (row-level
security). Publishing a run again replaces it: a job run twice leaves one copy.

## First set-up (administrator, once per database)

From a workstation allowed to reach the database, in a Python 3.11+ virtual environment, with the
administrator password (`/opt/a2vm-portal/secrets/postgres.txt` on a portal built by
`deploy/portal`) read from the server rather than typed:

```bash
pip install ./a2vm ./verdict
export PGPASSWORD="$(ssh root@portal.example.org cat /opt/a2vm-portal/secrets/postgres.txt)"
ADMIN="host=portal.example.org dbname=a2vm user=postgres sslmode=require"
verdict db init --dsn "$ADMIN"                       # tables, views, row-level security
verdict db grant a2vm_grafana '*' --dsn "$ADMIN"     # Grafana of the MSSP: every tenant
# verdict db grant acme_reader acme --dsn "$ADMIN"   # a tool limited to one tenant
unset PGPASSWORD
```

`grant` prints the role's password once: give it to the tool that reads, never paste it elsewhere.
`verdict db grant ROLE TENANT… --rotate` gives an existing role a new password (printed once).

### Upgrading from schema version 1 (v0.11.5)

Run `verdict db init` once, as above, before the first daily run of v0.11.6: the upgrade only adds
columns, a view and a function, keeps every run already published and re-grants the existing
reading roles. Until then the `publish` job stops with "the reporting database is at schema
version 1 … run `verdict db init`" (exit code 3, a warning) and publishes nothing. Runs published
before the upgrade have no severity, product or source: the new dashboards count them as
`Unknown` / `unknown`.

### Upgrading to schema version 3 (v0.18.1)

Run `verdict db init` once, as above, before the first daily run of v0.18.1: it adds the scans of
the assets, the last observation of each finding per source, the views `run_pairs`,
`finding_closures` and `latest_asset_scans` (the remediation dashboard), keeps every run and
re-grants the reading roles. Until then `publish` stops with "schema version 2 … run `verdict db
init`" (exit code 3, a warning). The first run published after the upgrade has nothing to compare
its scans with: the findings gone between the last run before and the first run after come out
"gone without a new scan"; the next days count fixes.

### Upgrading to schema version 4 (v0.19.0)

Run `verdict db init` once, as above, before the first daily run of v0.19.0: it adds the table
`coverage`, the views `coverage_facts` and `latest_coverage`, the coverage totals of each run and
the configuration item of each asset, keeps every run and re-grants the reading roles. Until then
`publish` stops with "schema version 3 … run `verdict db init`" (exit code 3, a warning). Then
import the dashboard `coverage` (and its French version).

### Upgrading to schema version 6 (v0.22.2)

Run `verdict db init` once, before the first daily run of v0.22.2: it adds the table
`declared_fixes` (the dates the team declared in the ITSM, read from the dispatch service) and the
columns `last_vulnerable`, `first_clean`, `declared_at`, `deadline` and `fix_status` of the view
`finding_closures` (when the fix happened, `docs/sla.md` §4), and re-grants the reading roles. Until
then `publish` stops with "schema version 5 … run `verdict db init`" (exit code 3, a warning). Then
import the dashboard `sla` again (two tables: the fixes against the SLA when they happened, those
missed or to verify).

### Upgrading to schema version 5 (v0.21.0)

Run `verdict db init` once, as above, before the first daily run of v0.21.0: it adds the priority of
the client's SLA to each decision (priority, rule, start, SLA due date), the SLA counts of each run,
and the columns `sla_status`, `deadline` and `within_sla` of the views, keeps every run and re-grants
the reading roles. Until then `publish` stops with "schema version 4 … run `verdict db init`" (exit
code 3, a warning). Then import the dashboard `sla` (and its French and RSSI versions). The runs
published before, and the clients without an SLA, have no priority: the dashboard shows them in no
priority (`docs/sla.md`).

## Client projects

CI/CD variables of the client project (Settings > CI/CD > Variables):

| Key | Value | Type and visibility |
| --- | --- | --- |
| `A2VM_REPORTING_DSN` | `postgresql://a2vm_writer:PASSWORD@portal.example.org/a2vm` | Variable, **Masked and hidden**, protected |
| `A2VM_REPORTING_CA` | The database's certificate (`/opt/a2vm-portal/pg/server.crt`), from `-----BEGIN` to `-----END` | File (or Variable), visible, protected |
| `A2VM_REPORTING_DSN_<NAME>`, `A2VM_REPORTING_CA_<NAME>` | Optional (v0.20.3): the database of another portal, e.g. `A2VM_REPORTING_DSN_CLIENT` for the client's own portal; as the two above | As the two above |

The URI form has no space, so GitLab can mask it; the writer password generated by
`deploy/portal` has only letters and digits, so it needs no escaping in the URI. The key=value
form (`host=… dbname=a2vm user=a2vm_writer password=…`) still works, but GitLab cannot mask it:
store it as a File variable, which keeps it out of the job logs but visible to the project's
maintainers in the settings.

With them, the daily pipeline gets a `publish` job after `triage`; its log reads
`<client>: run … published as #N (… decisions, … assets, …)`. Without them, nothing changes. With
the certificate the server is verified (`verify-full`: the host in the string must be the
portal's name); without it the connection is encrypted only. The database must accept the
runner's public address (security group and `pg_hba.conf` of the portal: `admin_ips`). An invalid
string is reported without quoting it, since it holds a password.

## Several portals (v0.20.3)

A run publishes into the database of every portal of its tenant: `A2VM_REPORTING_DSN` and each
`A2VM_REPORTING_DSN_<NAME>` (with its `A2VM_REPORTING_CA_<NAME>`); on Kubernetes `deploy-k8s`
copies them into the tenant's Secret (`reporting-dsn-<name>`). One that fails is a warning (exit 3)
and does not stop the others; the log names each (`<client> [<name>]: run … published as #N`).
Each database is set up once (`verdict db init`) and keeps its own history from its first run. A
typical set: the operator's portal in its cluster (every tenant), and one at a client, on the
client's premises, that only this client's runs feed.

## Portal on Kubernetes (`deploy/charts/a2vm-portal`, v0.20.3)

The reporting database (a CloudNativePG cluster, database `a2vm`, writer `a2vm_writer`) and Grafana,
its data source and the dashboards of the version provisioned in the folder "A2VM" (and, with
`dashboards.dispatchUrl`, the RSSI versions with their links in "A2VM — requests for remediation");
after each install and upgrade a job runs `verdict db init` and gives Grafana its reading role,
limited to `tenants`. Needs the CloudNativePG operator (`deploy/cnpg/README.md`).

```bash
helm upgrade --install portal deploy/charts/a2vm-portal -n a2vm-portal --create-namespace \
  --set image.registry=<registry>/vulnops/a2vm --set grafana.host=portal.apps.example.org \
  --set 'database.writerNamespaces={a2vm-lab}' --set 'dashboards.languages={en,fr}' \
  --set dashboards.dispatchUrl=https://dispatch-lab.apps.example.org
```

- **Grafana's admin**: user `admin`, password in the Secret `portal-portal-grafana`, key
  `admin-password`, read where it is: `kubectl -n a2vm-portal get secret portal-portal-grafana -o
  jsonpath='{.data.admin-password}' | base64 -d | pbcopy`.
- **Sign-in** (`grafana.oidc.*`): a client of the identity provider with the redirect URI
  `https://<host>/login/generic_oauth`; its secret in the Secret `portal-portal-oidc`, key
  `oidc-client-secret`, made by hand; `viewers` and `admins` groups; anyone else is refused.
- **Tenants in the same cluster** publish with the writer's connection string, the URI of the
  Secret `portal-portal-db-app` (key `uri`, host `portal-portal-db-rw.a2vm-portal`) and the CA of
  `portal-portal-db-ca` (key `ca.crt`), as `A2VM_REPORTING_DSN` and `A2VM_REPORTING_CA` of each
  tenant project; their namespaces in `database.writerNamespaces` (NetworkPolicy).
- **Publishers outside the cluster** (GitLab runners, another site): `database.external.allowFrom`
  (their addresses) makes a LoadBalancer Service to the primary instance, open to them only.
- **A client's portal**: the same chart in the client's cluster with `tenants={<client>}`, its
  writer URI and CA given to the tenant project as `A2VM_REPORTING_DSN_CLIENT` and
  `A2VM_REPORTING_CA_CLIENT`.
- **Moving from a portal VM**: `pg_dump --schema=a2vm` on the old database, `pg_restore` into the new
  one (as `a2vm_writer`), then the tenants' variables; `verdict db init` brings it to the version.

## Grafana

1. Connections > Data sources > Add > PostgreSQL: name `A2VM`, host `postgres:5432` (on the
   portal built by `deploy/portal`; else the database's address), database `a2vm`, user
   `a2vm_grafana` and the password from `db grant`, TLS mode `require`, version 16 or later.
   Save & test.
2. Dashboards > New > Import, once per dashboard: upload the output of
   `verdict grafana dashboard NAME` (or the file `verdict/src/verdict/restitution/grafana/NAME.json`),
   choose the data source of step 1. Importing again replaces the dashboard of the same uid.
   For French readers: `verdict grafana dashboard NAME --language fr` (or `NAME.fr.json`), a
   dashboard of its own (uid `<uid>-fr`) with the same queries and French titles and columns.
3. RSSI versions (v0.20.0, D18): `verdict grafana dashboard remediation --rssi`, `coverage --rssi` and `sla --rssi` (v0.21.0)
   (with `--language fr` too; files `*.rssi.json`, `*.rssi.fr.json`, uid `<uid>-rssi`): the same
   dashboards with a link "Remediate" on each asset and in their header, to the page of the requests
   for remediation of pillar 4. Grafana asks the page's address at import (`https://<A2VM_DISPATCH_HOST>`).
   Import them in a folder of their own, open to the persons who may ask for remediation
   (`docs/dispatch.md` §3); the reading versions stay as they are.

| `NAME` | Dashboard | Counts | Content |
| --- | --- | --- | --- |
| `assets` | A2VM — which assets to fix first | Exposures: one CVE on one asset | Counters: exposures, assets concerned, KEV exposures, ACT exposures, assets with ACT, overdue, share with a fix, EPSS ≥ 10 %; decision × severity matrix and its KEV part; assets ranked (ACT, KEV, overdue, critical) with the change of ACT; trend per day; exposures per zone and exposure |
| `cves` | A2VM — which CVEs to fix first | Distinct CVEs; a CVE takes the most urgent decision among its findings | Counters: distinct CVEs, KEV CVEs, KEV exposures, CVEs decided ACT, share with a fix, EPSS ≥ 10 %; decision × severity matrix and its KEV part; CVEs ranked (decision, KEV, EPSS, CVSS) with "new" or the earlier decision; trend per day; products with the most CVEs |
| `coverage` | A2VM — assets and scan coverage (v0.19.0) | Host of the latest run, against the CMDB and the means of detection its class expects | Covered share, in production, never scanned, stale, partial, not in the CMDB, retired but alive, not scannable; one row per host with its class, CMDB status, criticality, coverage, means missing and the last date each means (OpenVAS, Trivy, dnf, external scan, other) saw it; coverage per class; covered share run after run |
| `remediation` | A2VM — remediation (v0.18.1) | Findings fixed: gone from a run while their asset was scanned again by the source that had seen them | Fixed findings, mean days to fix an ACT, share of ACT and ATTEND fixed on time (BOD 26-04), gone without a new scan, assets not scanned for 7 days, reopened; fixed per day; time to fix per level; recently fixed (with the priority, its SLA due date and whether it was met, v0.21.0); assets by last scan |
| `sla` | A2VM — priorities and SLA (v0.21.0) | Decisions of the latest run of each client with a priority of its SLA; findings fixed in the time range | Open with a priority, past their SLA due date, SLA due within 7 days, share fixed within the SLA and the same findings within BOD 26-04, ACT and ATTEND in no priority; per priority (open, overdue, due soon, fixed, fixed within the SLA, mean days); overdue per day; overdue decisions and those due within 7 days, with the BOD 26-04 due date (`docs/sla.md`) |
| `overview` | A2VM — overview of a client | Findings of the latest run | One client: totals per level, overdue, due within 7 days, to review, exposure gaps, trend run after run, decisions to act on, assets, detection sources |

The `assets` and `cves` dashboards share their variables, kept when moving from one to the other
(links at the top):

| Variable | Content |
| --- | --- |
| Client | One, several or all clients the reading role sees |
| Snapshot | A day: for each client chosen, its latest run on or before that day (latest day first) |
| Compared with | An earlier day (the previous snapshot by default), or `none`; the arrows of the counters show the change since it |
| Scanner, Known exploited (KEV), SSVC decision, Severity (CVSS), EPSS band, Product type | Filters; severity is the CVSS rating of the metric the decision used (Critical 9.0+, High 7.0+, Medium 4.0+, Low, Unknown without a score); EPSS bands < 10 %, 10–50 %, ≥ 50 %, N/A; product type from the CPE part of the product (application, os, hardware, unknown) |

One Grafana organisation per client and a reading role limited to that client keep clients apart
when the portal is opened to them (HLD D13).

The dashboards are built by `scripts/make_grafana_dashboards.py`; change the script, not the JSON.
The test suite runs every panel query against PostgreSQL as Grafana sends it.
