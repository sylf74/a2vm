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

vulnops-profiles validate clients/*.yaml
scripts/run-pipeline.sh --fixtures tests/fixtures --since 2099-10-01 --include-updated   # offline demo
scripts/run-pipeline.sh --since 26h                 # real CVEs of the last 26 hours + KEV additions
scripts/run-pipeline.sh --cve CVE-2024-3400
```

With scanner collection over SSH (see `docs/scanning.md`):

```bash
TARGETS=config/targets/lab.yaml scripts/run-pipeline.sh --since 26h
```

Or stage by stage:

```bash
vulnops-detect collect config/targets/lab.yaml --out work/detect     # read-only scans over SSH
vulnops-intel collect --since 26h --detect work/detect --out work/records.json
vulnops-detect inventory clients/*.yaml --records work/records.json --out work/detect
vulnops-assets build clients/*.yaml --detect work/detect --out work/assets
verdict run clients/*.yaml --records work/records.json --assets work/assets --out output
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

One YAML file per client in `clients/`, validated against
`core/src/vulnops/core/schemas/client_profile.schema.json` (schema version 2; version 1 profiles
remain valid):

- `assets`: declared assets or product families, for inventory matching (optional);
- `rules`: exposure, criticality and owner for discovered hosts, by host name / FQDN glob or CIDR;
- `defaults`: the client's default assumptions; absent, the worst case applies.

See `clients/example-client.yaml` (declared inventory only) and `clients/lab.yaml` (scanners +
rules + declared appliances). These files describe client infrastructure: keep access restricted.

## Local LLM

Any OpenAI-compatible server with JSON-schema structured output (vLLM, SGLang). Enable it in
`config/settings.yaml` or with `VULNOPS_LLM_ENABLED`, `VULNOPS_LLM_BASE_URL`,
`VULNOPS_LLM_MODEL` (the former `VERDICT_*` names still work). Each stage prints the LLM
configuration it received at start-up, and the cause of any LLM fallback.

## GitLab CI

Lint, tests and profile validation on every push. The data pipeline runs as five jobs —
`collect` → `intel` → `detect` → `assets` → `triage`, each passing `work/` to the next as an
artifact — on a schedule (`TRIAGE_MODE=daily`) or by hand (`TRIAGE_MODE=manual`, optional
`TRIAGE_CVES`), on a runner tagged `llm-lan`. `collect` runs only when the `VULNOPS_SSH_KEY` file
variable exists. Reports and the asset inventory are kept 30 days, intermediate files 7 days.

## Repository layout

```
core/ intel/ detect/ assets/ verdict/      one Python package per stage (namespace vulnops.*)
remediate/                                 not started
clients/                                   client profiles
config/settings.yaml                       settings shared by all stages
config/targets/                            SSH collection targets per client
docs/scanning.md                           read-only scanner set-up
tests/                                     tests and offline fixtures
scripts/run-pipeline.sh                    the CI pipeline, locally
.gitlab/CODEOWNERS                         one owner per stage
```
