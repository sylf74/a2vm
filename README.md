# A2VM — AI-Assisted Vulnerability Management

A2VM is the project that brings the pillars of the platform together: each pillar is an
independent package with its own command, and they meet only through `a2vm`, the common contract
(data model, exchange files and their schemas, settings, client profiles, LLM client, extension
points). Decisions are deterministic (CISA SSVC tables + per-client policy); AI proposes and
writes — it fills flagged gaps, proposes uncertain matches and writes rationales — but never
decides.

```
a2vm/        common contract              model, schemas, settings, profiles, LLM client, extension points
via/        1. VIA (Vulnerability Intelligence: Advanced, AI-assisted, Alerting)
              via collect                public sources + CTI                              -> work/records.json
              via watch / send           watch on each client's estate, alert sheets       -> alerts/
detect/     2. Vulnerability Detection   scanners + declared inventory                     -> work/detect/<client>/<source>.json
verdict/    3. Triage & Prioritization
              verdict assets build       asset context consolidated per client             -> work/assets/<client>/
              verdict run                CISA SSVC + policy, French rationale              -> output/<client>/<date>/
remediate/  4. Dispatch & Capitalization (not started)
```

The pillars never import one another (a test checks it): each reads and writes only the common
model, and every exchange file is validated against its JSON Schema on write and on read. When a
pillar needs a capability of another one (the watch needs asset matching from detect and the
remediation delay from verdict), it asks `a2vm.extensions`, which the owner fills through a
Python entry point. The design is described in `docs/hld/` (high level) and `docs/lld/` (per
pillar).

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate        # PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt                 # a2vm + every pillar, editable, + pytest and ruff

a2vm validate examples/*/client.yaml
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
detect plan targets.yaml --profile client.yaml                # what would be scanned
detect collect targets.yaml --out work/detect                 # read-only scans over SSH
via collect --since 26h --detect work/detect --out work/records.json
detect inventory client.yaml --records work/records.json --out work/detect
verdict assets build client.yaml --detect work/detect --out work/assets
verdict run client.yaml --records work/records.json --assets work/assets --out output
```

## Pillars

**VIA, intel — Vulnerability Intelligence** (`via collect`) — builds one vulnerability
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

**detect — Detection** (`detect`) — writes one detection file per client and source:
asset observations (what a source saw) and findings (asset × CVE, with package, installed and
fixed versions).
Since v0.13.0, collectors near the client networks (`detect agent`) push their detections to
the detection service of the tenant in the cluster (`detect serve`), and the daily run reads them
(`detect fetch`): `docs/collectors.md`.

| Source | Command | Covers |
| --- | --- | --- |
| `trivy` | `collect` (SSH) or `import` | Ubuntu, Debian, Rocky/RHEL 8–9 hosts, container images |
| `dnf-updateinfo` | `collect` (SSH) or `import` | Rocky/RHEL 10 hosts (not covered by Trivy) |
| `inventory` | `inventory` | assets declared in the client profile, matched against CVE records by CPE, names, aliases and vendor version ranges; fuzzy matches confirmed by the LLM or flagged |

Collection is read-only: one command per host over SSH with a dedicated unprivileged account, at
the lowest CPU and I/O priority, no file-system traversal, no network scan (`docs/scanning.md`).
Windows and appliances are declared in the profile until a network scanner or a Windows
collector is added.

**verdict, assets — Asset context** (`verdict assets build`) — consolidates the observations of a client
into its inventory and re-keys its findings on consolidated assets:

- reconciliation: host observations sharing an FQDN, a short host name or an address are one asset;
- attributes (exposure, mission prevalence, public well-being impact, owner), first source wins:
  declared in the profile → profile rule (host name / FQDN glob, CIDR) → source → default
  assumption (the client's `defaults`, else the worst case: open, essential);
- every default assumption is named in the decision, in the rationale and flags the row for review.

The inventory is rebuilt at each run for now; history comes with the PostgreSQL storage.

**verdict, decision — Triage & Prioritization** (`verdict run`) — one decision per finding:

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

The SSVC tables are the official CERT/CC data files (`verdict/src/verdict/data/`,
MIT (SEI)-style license, see `LICENSE-SSVC`). The LLM never decides; it writes rationales for ACT
and ATTEND decisions only (`llm.rationale_for`), the template covers TRACK. Rationales name the
fixed packages reported by scanners.

## Client profiles

One YAML file per client (`client.yaml` of the client project), validated against
`a2vm/src/a2vm/schemas/client_profile.schema.json` (schema version 2; version 1 profiles
remain valid):

- `assets`: declared assets or product families, for inventory matching (optional);
- `rules`: exposure, criticality and owner for discovered hosts, by host name / FQDN glob or CIDR;
- `defaults`: the client's default assumptions; absent, the worst case applies.

See `examples/example-client/` (declared inventory only) and `examples/lab/` (scanners + rules +
declared appliances, and the client project template): both are fictitious. Real profiles and scan
targets describe client infrastructure and never go in this repository.

## Local LLM

Any OpenAI-compatible server with JSON-schema structured output (vLLM, SGLang). Enable it in
`config/settings.yaml` or with `A2VM_LLM_ENABLED`, `A2VM_LLM_BASE_URL`,
`A2VM_LLM_MODEL` (the former `VERDICT_*` names still work). Each stage prints the LLM
configuration it received at start-up, and the cause of any LLM fallback.

## Google Threat Intelligence (optional)

With a GTI licence, `A2VM_GTI_ENABLED=true` and a masked `GTI_API_KEY` variable, the intel stage
adds GTI's exploitation state to each CVE (only CVE ids are sent). Confirmed exploitation counts as
active in SSVC and makes a watch alert urgent; GTI's licensed prose stays with the analysts
(`docs/gti.md`).

## Watch mode: alerts

Every 10 minutes, each client project checks CERT-FR, CISA KEV and new critical CVEs, matches them
to the client's declared assets and watchlist, drafts an alert sheet in French and mails it to the
analysts; one click on the pipeline's manual job sends it to the client (`docs/alerts.md`).

The daily triage also writes `dashboard.html`: decision counts, findings per asset, remediation
deadlines and the ACT list, in one self-contained page.

## Multi-tenant deployment (GitLab)

```
vulnops/                 group: group runner (tag llm-lan), shared variables (LLM endpoint)
├── a2vm                  this code project: lint, tests, examples; releases are tags vX.Y.Z
└── clients/             one private project per client: client.yaml, targets.yaml, variables
    └── <client>         (scan key), schedule, artifacts — nothing shared between clients
```

Each client project includes `templates/client-pipeline.yml` at a fixed tag: `validate` on every
push; on a schedule or by hand (optional `TRIAGE_CVES`), `collect` → `via` → `detect` →
`assets` → `triage`, each passing `work/` to the next. Reports and the asset inventory are kept 30
days in the client project, intermediate files 7 days. A client moves to a new A2VM version
by changing the tag in its `.gitlab-ci.yml`. Set-up: `docs/deployment.md`.

## Repository layout

```
a2vm/                                       common contract (package and command `a2vm`)
via/ detect/ verdict/                      one package and one command per pillar
remediate/                                 not started
config/settings.yaml                       default settings (a client project may override them)
templates/client-pipeline.yml              pipeline included by every client project
examples/                                  fictitious client projects (profile, targets, CI)
docs/hld/                                  high-level design: product strategy and one chapter per pillar
docs/lld/                                  low-level design, one per pillar
docs/deployment.md                         GitLab groups, runner, code and client projects
docs/scanning.md                           read-only scanner set-up
docs/openvas.md                            OpenVAS network scans (Greenbone), mutual TLS to GMP
docs/alerts.md                             watch mode, sources, alert sheets, mail
docs/gti.md                                Google Threat Intelligence connector
tests/                                     tests and offline fixtures
scripts/run-pipeline.sh                    the CI pipeline, locally
scripts/build-hld.sh                       the HLD assembled into one document
.gitlab/CODEOWNERS                         one owner per pillar
```

## License

Proprietary, all rights reserved, pending a licensing decision (see `LICENSE` and `NOTICE`);
earlier versions were published under AGPL-3.0-only. Contributions: `CONTRIBUTING.md`.
Security issues: `SECURITY.md`.
