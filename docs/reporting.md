# Reporting database and Grafana (v0.11.5)

Every daily run publishes its reporting dataset (`output/<client>/reporting.json`) into a
PostgreSQL database; Grafana, and later the company's reporting tool, read that database and
never GitLab (HLD strategy D14, D3). One row set per run is kept, so the dashboards show trends.

```
daily pipeline ── triage ── publish ──▶ PostgreSQL (schema a2vm) ◀── Grafana (one reading role)
                                 writer role                    ◀── Qlik Sense (later)
```

Package `dispatch` (pillar 4); it reads the reporting dataset only and imports no other pillar.

## Tables (schema `a2vm`, version 1)

| Table / view | Content |
| --- | --- |
| `runs` | One row per tenant and run: version, policy hash, pipeline, totals per level, assets per level, to review, assumed inputs, overdue, due within 7 days, exposure gaps |
| `decisions` | One row per decision of the run: finding, asset, zone, exposure and its source, CVE, title, level, SSVC outcome, BOD 26-04 timeline, first seen, due date, KEV, EPSS, review flag, rationale |
| `assets`, `exposure_gaps`, `sources` | Per run: assets with their counts per level; exposure gaps; detection sources and their latest observation |
| `latest_runs`, `latest_decisions`, `latest_assets`, `latest_exposure_gaps` | The latest run of each tenant and its rows |
| `tenant_roles` | Which tenants a reading role sees (`*` = all) |

The writer role owns the tables. Reading roles get `SELECT` and see only their tenants (row-level
security). Publishing a run again replaces it: a job run twice leaves one copy.

## First set-up (administrator, once per database)

From a workstation allowed to reach the database, with the administrator password
(`/opt/a2vm-portal/secrets/postgres.txt` on a portal built by `deploy/portal`):

```bash
pip install ./a2vm ./dispatch
ADMIN="host=portal.example.org dbname=a2vm user=postgres sslmode=require"
dispatch db init --dsn "$ADMIN"                       # tables, views, row-level security
dispatch db grant a2vm_grafana '*' --dsn "$ADMIN"     # Grafana of the MSSP: every tenant
# dispatch db grant acme_reader acme --dsn "$ADMIN"   # a tool limited to one tenant
```

`grant` prints the role's password once: give it to the tool that reads. Run `db init` again after
an upgrade that changes the schema, then `db grant` again for each reading role.

## Client projects

CI/CD variables of the client project (or of the group `vulnops/clients`):

| Key | Value | Options |
| --- | --- | --- |
| `A2VM_REPORTING_DSN` | `host=portal.example.org dbname=a2vm user=a2vm_writer password=…` | Masked, protected |
| `A2VM_REPORTING_CA` | The database's certificate (`/opt/a2vm-portal/pg/server.crt`) | File |

With them, the daily pipeline gets a `publish` job after `triage`; its log reads
`<client>: run … published as #N (… decisions, … assets, …)`. Without them, nothing changes. With
the certificate the server is verified (`verify-full`: the name in `host=` must be the portal's);
without it the connection is encrypted only. The database must accept the runner's public address.

## Grafana

1. Connections > Data sources > Add > PostgreSQL: host `postgres:5432` (on the portal built by
   `deploy/portal`; else the database's address), database `a2vm`, user `a2vm_grafana` and the
   password from `db grant`, TLS mode `require`, version 16 or later. Save & test.
2. Dashboards > New > Import: paste the output of `dispatch grafana dashboard` (or the file
   `dispatch/src/dispatch/grafana/a2vm-dashboard.json`), choose the data source of step 1.
3. The dashboard shows one client at a time (list at the top): totals per level, overdue and due
   within 7 days, to review, exposure gaps, trend run after run, findings per exposure, the
   decisions to act on, assets, detection sources.

One Grafana organisation per client and a reading role limited to that client keep clients apart
when the portal is opened to them (HLD D13).

The dashboard is built by `scripts/make_grafana_dashboard.py`; change the script, not the JSON.
