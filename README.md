# vulnops — AI-assisted Vulnerability Pipeline

A vulnerability data pipeline in four stages linked by a common data model. Decisions are
deterministic (CISA SSVC tables + per-client policy); the LLM assists — it fills flagged gaps,
confirms uncertain matches and writes rationales — but never decides.

```
intel/      vulnerability records    cvelistV5 (CNA + CISA ADP), CISA KEV, FIRST EPSS  -> work/records.json
detect/     findings per client      declared inventory today, scanners next           -> work/findings/<client>.json
verdict/    decisions per finding    CISA SSVC + policy, French rationale by a local LLM -> output/<client>/<date>/
remediate/  (not started)            actions, plans, deadlines
core/       common model             data classes, JSON Schemas of the exchange files, settings, profiles, LLM client
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

Or stage by stage:

```bash
vulnops-intel collect --since 26h --out work/records.json
vulnops-detect inventory clients/*.yaml --records work/records.json --out work/findings
verdict run clients/*.yaml --records work/records.json --findings work/findings --out output
```

## Stages

**intel** (`vulnops-intel collect`) — selects CVEs (`--cve`, `--cve-file`, `--since` = cvelistV5
delta log + KEV additions), fetches each CVE JSON 5 record and merges its KEV entry and EPSS
score into one vulnerability record. Rejected and missing CVEs are reported as errors.

**detect** (`vulnops-detect inventory`) — the inventory scanner: matches records against the
assets declared in each client profile (CPE, names, aliases, vendor version ranges) and writes
one findings file per client. Fuzzy product-name matches are confirmed or rejected by the LLM
when enabled, flagged for review otherwise. Scanner connectors (Trivy first) will write the
same findings format.

**verdict** (`verdict run`) — one decision per finding:

```
Exploitation       KEV -> CISA ADP (Vulnrichment) -> exploit reference -> none (review)
Automatable        CISA ADP -> CVSS heuristic -> LLM -> policy default (review)
Technical Impact   CISA ADP -> CVSS heuristic -> LLM -> policy default (review)
Mission/Well-being client profile          Publicly exposed   client profile
        -> CISA Coordinator v2.0.3 table -> track | track* | attend | act
        -> CISA BOD 26-04 table          -> remediation timeline
        -> policy (config/settings.yaml)  -> ACT / ATTEND / TRACK + traced escalations
        -> rationale: LLM text behind a guard, template fallback
```

The SSVC tables are the official CERT/CC data files (`verdict/src/vulnops/verdict/data/`,
MIT (SEI)-style license, see `LICENSE-SSVC`). The LLM never decides.

## Client profiles

One YAML file per client in `clients/`, validated against
`core/src/vulnops/core/schemas/client_profile.schema.json`. See `clients/example-client.yaml`.
These files describe client infrastructure: keep access to them restricted.

## Local LLM

Any OpenAI-compatible server with JSON-schema structured output (vLLM, SGLang). Enable it in
`config/settings.yaml` or with `VULNOPS_LLM_ENABLED`, `VULNOPS_LLM_BASE_URL`,
`VULNOPS_LLM_MODEL` (the former `VERDICT_*` names still work). Each stage prints the LLM
configuration it received at start-up, and the cause of any LLM fallback.

## GitLab CI

Lint, tests and profile validation on every push. The data pipeline runs as three jobs —
`intel` → `detect` → `triage`, each passing its output to the next as an artifact — on a
schedule (`TRIAGE_MODE=daily`) or by hand (`TRIAGE_MODE=manual`, optional `TRIAGE_CVES`), on
a runner tagged `llm-lan`. Reports are kept 30 days, intermediate files 7 days.

## Repository layout

```
core/ intel/ detect/ verdict/ remediate/   one Python package per stage (namespace vulnops.*)
clients/                                   client profiles
config/settings.yaml                       settings shared by all stages
tests/                                     tests and offline fixtures
scripts/run-pipeline.sh                    the CI pipeline, locally
.gitlab/CODEOWNERS                         one owner per stage
```
