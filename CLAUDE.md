# A2VM — notes for Claude (and any new contributor)

A2VM (AI-Assisted Vulnerability Management) turns vulnerability intelligence, scanner results and
each client's asset context into one prioritised decision per finding (ACT / ATTEND / TRACK),
explained, reviewed by an analyst, and restituted in reports and dashboards.

Read first: `docs/hld/00-product-strategy.md` (goals, decisions D1–D15, contracts), then the
chapter and the LLD of the pillar you touch (`docs/hld/`, `docs/lld/`). Operating guides are the
other files of `docs/`.

## Layout

| Path | What |
| --- | --- |
| `a2vm/` | Common contract: data model, JSON schemas of the exchange files, settings, profiles, LLM client and guard, extension points |
| `via/` | Pillar 1, intelligence (records) and watch (alerts) |
| `detect/` | Pillar 2, detection: SSH collection, OpenVAS, declared inventory, external scan; collector agent and detection service (`detect agent`, `detect serve`, `detect fetch`) |
| `verdict/` | Pillar 3, asset context, SSVC decision, restitution (reporting database, Grafana); decision service and tool server of the analysts' chat (`verdict serve`, `verdict push`, `verdict tools`) |
| `templates/client-pipeline.yml` | The pipeline every tenant project includes at a version tag |
| `examples/` | Fictitious tenants (`lab`, `demo-industrie`) |
| `deploy/portal/` | Terraform and cloud-init of the reporting database and Grafana |
| `deploy/charts/a2vm-tenant/` | Helm chart: a tenant's daily run as a Kubernetes CronJob (D15 step 1, `docs/kubernetes.md`), its detection service (D15 step 2, `docs/collectors.md`), its decision service (D15 step 3) and the analysts' chat (`docs/chat.md`) |
| `deploy/intake/` | Script of the job `deploy-k8s` that turns the collectors' tokens into digests (stdlib and PyYAML only) |
| `deploy/chat/` | Script of the job `deploy-k8s` that writes the chat's values (stdlib only) |
| `deploy/collector/` | Install script of a collector on its VM (`docs/collectors.md` §2) |
| `images/` | Dockerfile of the pillar images (one per pillar, built by the `images` job on tags) |
| `scripts/` | Generators of committed files: dashboards, decision diagrams, neutral Word template |

Pillars import only `a2vm` and themselves, never another pillar (D12, `tests/test_architecture.py`);
a capability shared across pillars goes through `a2vm.extensions`.

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
- Exchange files are versioned (`a2vm.<name>/1`): within a version fields are only added; a field
  removed or changed in meaning makes `/2`.
- Commit messages end with `Co-Authored-By: Claude …` when Claude wrote the change; no link to a
  Claude session or conversation.
- Generated files are never edited by hand: change the script, run it, commit both
  (`scripts/make_grafana_dashboards.py`, `scripts/make_decision_diagrams.py`,
  `scripts/make_alert_template.py`).

## Checks before a merge request

```bash
pip install -r requirements-dev.txt
ruff check . && ruff format --check .
A2VM_TEST_DSN="host=localhost dbname=postgres user=postgres password=… sslmode=disable" pytest -q
python scripts/make_decision_diagrams.py --check
```

Without `A2VM_TEST_DSN` (a disposable PostgreSQL 16+), the database tests are skipped; the CI test
job always runs them.

## Releasing

1. Bump `version` in `a2vm/`, `via/`, `detect/`, `verdict/` `pyproject.toml`, `__version__` in
   `a2vm` and `via`, and `version`/`appVersion` of `deploy/charts/a2vm-tenant/Chart.yaml`; set the
   new tag in `examples/*/.gitlab-ci.yml` and `docs/deployment.md`; add the version to the roadmap
   table of the HLD (§11) and its release notes at the top of `CHANGELOG.md` (what changed, then
   what a tenant does to upgrade; `tests/test_v0140.py` checks the current version is there).
2. Merge, then tag `vX.Y.Z` on the default branch: the `release` job checks the versions, `images`
   builds the pillar images where a registry exists, and `sync-product-docs` publishes `docs/`
   where configured (`docs/deployment.md` §7).
3. Tenants move by changing `ref` and `A2VM_REF` in their `.gitlab-ci.yml`; a database schema change
   needs `verdict db init` once (`docs/reporting.md`).
