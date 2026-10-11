# vulnops — AI-assisted Vulnerability Pipeline

A vulnerability data pipeline in five stages linked by a common data model. Decisions are
deterministic (CISA SSVC tables + per-client policy); the LLM assists — it fills flagged gaps,
confirms uncertain matches and writes rationales — but never decides.

```
intel/      Vulnerability Intelligence   public sources + CTI (Google CTI planned)       -> work/records.json
detect/     Detection                    scanners (Trivy, dnf) + declared inventory      -> work/detect/<client>/<source>.json
assets/     Asset inventory              multi-tenant inventory consolidated per client  -> work/assets/<client>/
verdict/    Triage & Prioritization      CISA SSVC + policy, French rationale (local LLM) -> output/<client>/<date>/
remediate/  (not started)                actions, plans, deadlines
core/       common model                 data classes, exchange-file schemas, settings, profiles, LLM client
```

Each stage reads and writes only the common model, and every exchange file is validated
against its JSON Schema on write and on read. A new source, scanner or LLM engine plugs into
one stage without touching the others. The design is described in the architecture document
("vulnops — AI-assisted Vulnerability Pipeline: architecture").

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate        # PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt                 # every stage, editable, + pytest and ruff

vulnops-profiles validate examples/*/client.yaml
scripts/run-pipeline.sh --fixtures tests/fixtures --since 2099-10-01 --include-updated   # offline demo
scripts/run-pipeline.sh --since 26h                 # real CVEs of the last 26 hours + KEV additions
scripts/run-pipeline.sh --cve CVE-2024-3400
```

On a client project checked out next to this one (see `docs/deployment.md`), with scanner
collection over SSH (`docs/scanning.md`):

```bash
PROFILES=../homelab/client.yaml TARGETS=../homelab/targets.yaml scripts/run-pipeline.sh --since 26h
```

Or stage by stage:

```bash
vulnops-detect plan targets.yaml --profile client.yaml                # what would be scanned
vulnops-detect collect targets.yaml --out work/detect                 # read-only scans over SSH
vulnops-intel collect --since 26h --detect work/detect --out work/records.json
vulnops-detect inventory client.yaml --records work/records.json --out work/detect
vulnops-assets build client.yaml --detect work/detect --out work/assets
verdict run client.yaml --records work/records.json --assets work/assets --out output
```

## Stages

**intel — Vulnerability Intelligence** (`vulnops-intel collect`) — builds one vulnerability
record per CVE from two families of sources:

| Family | Source | What it adds | Status |
| --- | --- | --- | --- |
| Public | cvelistV5 (CNA + CISA ADP Vulnrichment) | CVE record, affected products, CISA SSVC decision points | in place |
| Public | CISA KEV | known active exploitation | in place |
| Public | FIRST EPSS | 30-day exploitation probability | in place |
| CTI | Google CTI | threat intelligence: exploitation in the wild, threat actors, exploit availability | planned |
| Public | vendor advisories (CSAF, RSS), CERT-FR | fixed versions, workarounds | planned |

CVE selection: `--cve`, `--cve-file`, `--since` (cvelistV5 delta log + KEV additions). Rejected
and missing CVEs are reported as errors. CTI sources are paid per request: they will be queried
only for CVEs that matter (with findings, or above a threshold), with a cache, and their API
keys come from CI/CD variables, never from the repository.

**detect — Detection** (`vulnops-detect`) — writes one detection file per client and source:
asset observations (what a source saw) and findings (asset × CVE, with package, installed and
fixed versions).

| Source | Command | Covers |
| --- | --- | --- |
| `trivy` | `collect` (SSH) or `import` | Ubuntu, Debian, Rocky/RHEL 8–9 hosts, container images |
| `dnf-updateinfo` | `collect` (SSH) or `import` | Rocky/RHEL 10 hosts (not covered by Trivy) |
| `inventory` | `inventory` | assets declared in the client profile, matched against CVE records by CPE, names, aliases and vendor version ranges; fuzzy matches confirmed by the LLM or flagged |

Collection is read-only: one command per host over SSH with a dedicated unprivileged account, at
the lowest CPU and I/O priority, no file-system traversal, no network scan (`docs/scanning.md`).
Windows and appliances are declared in the profile until a network scanner or a Windows
collector is added.

**assets — Asset inventory** (`vulnops-assets build`) — consolidates the observations of a client
into its inventory and re-keys its findings on consolidated assets:

- reconciliation: host observations sharing an FQDN, a short host name or an address are one asset;
- attributes (exposure, mission prevalence, public well-being impact, owner), first source wins:
  declared in the profile → profile rule (host name / FQDN glob, CIDR) → source → default
  assumption (the client's `defaults`, else the worst case: internet, essential);
- every default assumption is named in the decision, in the rationale and flags the row for review.

The inventory is rebuilt at each run for now; history comes with the PostgreSQL storage.

**verdict — Triage & Prioritization** (`verdict run`) — one decision per finding:

```
Exploitation       KEV -> CISA ADP (Vulnrichment) -> exploit reference -> none (review)
Automatable        CISA ADP -> CVSS heuristic -> LLM -> policy default (review)
Technical Impact   CISA ADP -> CVSS heuristic -> LLM -> policy default (review)
Mission/Well-being asset attributes        Publicly exposed   asset attribute exposure
        -> CISA Coordinator v2.0.3 table -> track | track* | attend | act
        -> CISA BOD 26-04 table          -> remediation timeline
        -> policy (config/settings.yaml)  -> ACT / ATTEND / TRACK + traced escalations
        -> rationale: LLM text behind a guard, template fallback
```

The SSVC tables are the official CERT/CC data files (`verdict/src/vulnops/verdict/data/`,
MIT (SEI)-style license, see `LICENSE-SSVC`). The LLM never decides; it writes rationales for ACT
and ATTEND decisions only (`llm.rationale_for`), the template covers TRACK. Rationales name the
fixed packages reported by scanners.

## Client profiles

One YAML file per client (`client.yaml` of the client project), validated against
`core/src/vulnops/core/schemas/client_profile.schema.json` (schema version 2; version 1 profiles
remain valid):

- `assets`: declared assets or product families, for inventory matching (optional);
- `rules`: exposure, criticality and owner for discovered hosts, by host name / FQDN glob or CIDR;
- `defaults`: the client's default assumptions; absent, the worst case applies.

See `examples/example-client/` (declared inventory only) and `examples/lab/` (scanners + rules +
declared appliances, and the client project template): both are fictitious. Real profiles and scan
targets describe client infrastructure and never go in this repository.

## Local LLM

Any OpenAI-compatible server with JSON-schema structured output (vLLM, SGLang). Enable it in
`config/settings.yaml` or with `VULNOPS_LLM_ENABLED`, `VULNOPS_LLM_BASE_URL`,
`VULNOPS_LLM_MODEL` (the former `VERDICT_*` names still work). Each stage prints the LLM
configuration it received at start-up, and the cause of any LLM fallback.

## Watch mode: alerts

Every 10 minutes, each client project checks CERT-FR, CISA KEV and new critical CVEs, matches them
to the client's declared assets and watchlist, drafts an alert sheet in French and mails it to the
analysts; one click on the pipeline's manual job sends it to the client (`docs/alerts.md`).

The daily triage also writes `dashboard.html`: decision counts, findings per asset, remediation
deadlines and the ACT list, in one self-contained page.

## Multi-tenant deployment (GitLab)

```
vulnops/                 group: group runner (tag llm-lan), shared variables (LLM endpoint)
├── vulnops              this code project: lint, tests, examples; releases are tags vX.Y.Z
└── clients/             one private project per client: client.yaml, targets.yaml, variables
    └── <client>         (scan key), schedule, artifacts — nothing shared between clients
```

Each client project includes `templates/client-pipeline.yml` at a fixed tag: `validate` on every
push; on a schedule or by hand (optional `TRIAGE_CVES`), `collect` → `intel` → `detect` →
`assets` → `triage`, each passing `work/` to the next. Reports and the asset inventory are kept 30
days in the client project, intermediate files 7 days. A client moves to a new vulnops version
by changing the tag in its `.gitlab-ci.yml`. Set-up: `docs/deployment.md`.

## Repository layout

```
core/ intel/ detect/ assets/ verdict/      one Python package per stage (namespace vulnops.*)
remediate/                                 not started
config/settings.yaml                       default settings (a client project may override them)
templates/client-pipeline.yml              pipeline included by every client project
examples/                                  fictitious client projects (profile, targets, CI)
docs/deployment.md                         GitLab groups, runner, code and client projects
docs/scanning.md                           read-only scanner set-up
tests/                                     tests and offline fixtures
scripts/run-pipeline.sh                    the CI pipeline, locally
.gitlab/CODEOWNERS                         one owner per stage
```
