# NGVM — notes for Claude (and any new contributor)

NGVM (Next-Generation Vulnerability Management) turns vulnerability intelligence, scanner results and
each client's asset context into one prioritised decision per finding (ACT / ATTEND / TRACK),
explained, reviewed by an analyst, and restituted in reports and dashboards.

Read first: `docs/hld/00-product-strategy.md` (goals, decisions D1–D22, contracts), then the
chapter and the LLD of the pillar you touch (`docs/hld/`, `docs/lld/`). Operating guides are the
other files of `docs/`; day-to-day operation: `docs/operations.md`.

## Layout

| Path | What |
| --- | --- |
| `ngvm/` | Common contract: data model, JSON schemas of the exchange files and OpenAPI contracts of the services, settings, profiles, LLM client and guard, CISA SSVC tables, matching of declared assets, connection to the tenant's database (`ngvm.db`) |
| `via/` | Pillar 1, intelligence (records) and watch (alerts); watch service, review page and sender on Kubernetes (`via serve`, `via service`); the shared intelligence service of every tenant and the radar of the watch team (`via intel-serve`, v0.22.0) |
| `detect/` | Pillar 2, detection: SSH collection, OpenVAS, declared inventory, external scan; collector agent and detection service (`detect agent`, `detect serve`, `detect fetch`) |
| `verdict/` | Pillar 3, asset context, SSVC decision, restitution (reporting database, Grafana); decision service and tool server of the analysts' chat (`verdict serve`, `verdict push`, `verdict tools`) |
| `dispatch/` | Pillar 4, dispatch: remediation tickets in the ITSM (iTop), followed until a scan confirms the fix; page of the requests for remediation (`dispatch serve`, `dispatch run`) |
| `templates/client-pipeline.yml` | The pipeline every tenant project includes at a version tag |
| `examples/` | Fictitious tenants (`lab`, `demo-industrie`) |
| `deploy/portal/` | Terraform and cloud-init of the reporting database and Grafana on a VM |
| `deploy/charts/ngvm-portal/` | Helm chart of a portal on Kubernetes: the reporting database (CloudNativePG) and Grafana with the dashboards provisioned (`docs/reporting.md`); its `dashboards/` are copies made by `scripts/make_grafana_dashboards.py` |
| `deploy/scanner/` | Terraform and cloud-init of the cloud scanner: Greenbone and the runner of the external projects (`docs/openvas.md` §5) |
| `deploy/charts/ngvm-tenant/` | Helm chart: a tenant's daily run as a Kubernetes CronJob (D15 step 1, `docs/kubernetes.md`), its detection service (D15 step 2, `docs/collectors.md`), its decision service (D15 step 3), the analysts' chat (`docs/chat.md`), the watch on Kubernetes (`NGVM_RUN_MODE`) and the review page of the alerts with the analysts' sign-in (`docs/sign-in.md`), the tenant's PostgreSQL (CloudNativePG `Cluster`) |
| `deploy/intake/` | Script of the job `deploy-k8s` that turns the collectors' tokens into digests (stdlib and PyYAML only) |
| `deploy/dispatch/` | Script of the job `deploy-k8s` that writes the values of the dispatch service (stdlib and PyYAML only) |
| `deploy/chat/` | Scripts of the job `deploy-k8s` that write the values of the chat and of the analysts' sign-in and review page (stdlib only) |
| `deploy/collector/` | Install script of a collector on its VM (`docs/collectors.md` §2) |
| `deploy/tofu/` | OpenTofu: the platform from machines reached by SSH (`modules/platform`, its scripts in `scripts/`), on machines that exist (`existing`) or created on Scaleway, Azure or a KVM host (`docs/platform.md`, D22); checked by `check.sh` |
| `deploy/cnpg/` | Installation of the CloudNativePG operator, once per Kubernetes cluster (the tenants' PostgreSQL, `docs/kubernetes.md` §5) |
| `images/` | Dockerfile of the pillar images (one per pillar, built by the `images` job on tags) |
| `scripts/` | Generators of committed files: dashboards, decision diagrams, architecture diagrams, neutral Word template |

Pillars import only `ngvm` and themselves, never another pillar (D12, `tests/test_architecture.py`).
What several pillars run is a library of `ngvm` (e.g. `ngvm.ssvc`, `ngvm.declared`); what a pillar
keeps for itself is reached through its HTTP API, whose contract is in `ngvm/schemas/openapi/`.
Each LLD lists, in its §1.1, the interfaces its pillar provides and consumes, and HLD §6 all of
them (`tests/test_interfaces.py`).

## Rules that are not negotiable

- **No real infrastructure or client data in the repository or its history**: invented names and
  documentation addresses only (`example.org`, `*.example`, 192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24). Client profiles, contacts and templates live in the tenant projects.
- **No secret in code, docs, commands or job logs**: CI/CD variables (masked, protected, File type
  where needed). Commands given to an operator read a secret from where it is stored rather than
  having it typed.
- **AI proposes, rules and people decide** (D4, D11): an LLM output is a proposal or a text, with a
  deterministic fallback, its source recorded, flagged for review; the SSVC tables and the policy
  take every decision. Client data goes only to the LLM endpoint approved for that tenant.
- **Scans are non-intrusive**, on addresses the client owns or authorised.
- **Docs change with the code**: the HLD chapter and the LLD of a pillar are updated in the same
  merge request; a change to a contract of HLD §6 is reviewed by every pillar that uses it.

## Conventions

- Repository text (code, comments, docs, commit messages) in English; plain, short sentences.
- Exchange files are versioned (`ngvm.<name>/1`): within a version fields are only added; a field
  removed or changed in meaning makes `/2`.
- Commit messages end with `Co-Authored-By: Claude …` when Claude wrote the change; no link to a
  Claude session or conversation.
- Generated files are never edited by hand: change the script, run it, commit both
  (`scripts/make_grafana_dashboards.py`, `scripts/make_decision_diagrams.py`,
  `scripts/make_alert_template.py`, `scripts/make_architecture_diagrams.py`).

## Checks before a merge request

```bash
pip install -r requirements-dev.txt
ruff check . && ruff format --check .
NGVM_TEST_DSN="host=localhost dbname=postgres user=postgres password=… sslmode=disable" pytest -q
python scripts/make_decision_diagrams.py --check
python scripts/make_architecture_diagrams.py --check
```

Without `NGVM_TEST_DSN` (a disposable PostgreSQL 16+), the database tests are skipped; the CI test
job always runs them. With it, the tests of the three services run on their files and on
PostgreSQL (a new database and role per test; the administrator connection needs CREATEDB and
CREATEROLE).

## Releasing

1. Bump `version` in `ngvm/`, `via/`, `detect/`, `verdict/`, `dispatch/` `pyproject.toml`, `__version__` in
   `ngvm` and `via`, and `version`/`appVersion` of `deploy/charts/ngvm-tenant/Chart.yaml` and
   `deploy/charts/ngvm-portal/Chart.yaml`; set the
   new tag in `examples/*/.gitlab-ci.yml` and `docs/deployment.md`; add the version to the roadmap
   table of the HLD (§11) and its release notes at the top of `CHANGELOG.md` (what changed, then
   what a tenant does to upgrade; `tests/test_v0140.py` checks the current version is there).
2. Merge, then tag `vX.Y.Z` on the default branch: the `release` job checks the versions, `images`
   builds the pillar images where a registry exists, and `sync-product-docs` publishes `docs/`
   where configured (`docs/deployment.md` §7).
3. Tenants move by changing `ref` and `NGVM_REF` in their `.gitlab-ci.yml`; a database schema change
   needs `verdict db init` once (`docs/reporting.md`).
