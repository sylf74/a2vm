# cve-triage

Triage of newly published CVEs against each client's asset profile, using the CISA SSVC decision
model. The decision is computed deterministically; a local LLM (optional) only fills gaps that are
then flagged for review, adjudicates uncertain product matches, and writes the French rationale.

Output per client and per run: `report.md` (French, ready for the client delivery), `triage.csv`
(one row per CVE × asset, `;`-separated) and `triage.json` (full detail and provenance).

## How a decision is made

```
CVE ids (--cve / --cve-file / --since)
  │
  ├─ CVE record (cvelistV5: CNA + CISA ADP "Vulnrichment")   KEV (CISA)   EPSS (FIRST)
  │
  ▼
match products against clients/<client>.yaml ── fuzzy name match? ── LLM confirms / human review
  │
  ▼
deployed versions affected?  ── all unaffected ──► "not affected" section
  │ affected / unknown
  ▼
SSVC inputs                                     source precedence
  Exploitation        none | poc | active       KEV → CISA ADP → "exploit" reference → none (review)
  Automatable         yes | no                  CISA ADP → CVSS heuristic → LLM → policy default (review)
  Technical Impact    partial | total           CISA ADP → CVSS heuristic → LLM → policy default (review)
  Mission/Well-being  low | medium | high       client profile (mission_prevalence, public_wellbeing_impact)
  Publicly exposed    yes | no                  client profile (exposure == internet)
  │
  ├─ CISA Coordinator v2.0.3 table ─► track | track* | attend | act
  ├─ CISA BOD 26-04 table          ─► remediation timeline (fix on upgrade … 3 days + forensics)
  ▼
policy (config/settings.yaml): mapping to ACT / ATTEND / TRACK + escalations (BOD timeline, EPSS)
  ▼
rationale: French template, or LLM text checked by a guard (template fallback)
```

The SSVC tables are the official CERT/CC data files (`src/cve_triage/data/`, MIT (SEI)-style
license, see `LICENSE-SSVC`), not a re-typed copy.

Default mapping: `act → ACT`, `attend → ATTEND`, `track* → ATTEND`, `track → TRACK`, then:
BOD timeline "3 days…" → ACT, "14 days" → at least ATTEND, EPSS ≥ 0.1 → at least ATTEND.
Every escalation is written in the row's `reasons`. All of it is configurable.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate        # PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"

cve-triage validate clients/*.yaml
# offline demo on the test fixtures
cve-triage run clients/example-client.yaml --fixtures tests/fixtures --since 2099-10-01 --cve CVE-2024-3400
# real run: CVEs published in the last 26 hours, plus KEV additions
cve-triage run clients/*.yaml --since 26h
# CVEs from the daily watch (one id per line, # comments allowed)
cve-triage run clients/acme.yaml --cve-file watch-2026-10-10.txt
```

Reports land in `output/<client-id>/<date>/`.

## Client profiles

One YAML file per client in `clients/`, validated in CI against
`src/cve_triage/schemas/client_profile.schema.json`. See `clients/example-client.yaml`.

An asset is a product family deployed in one context: same exposure, same criticality, same
owner. If the same product is both Internet-facing and internal, declare two assets.

- `vendor` / `product` / aliases / `cpe`: used to match the CVE record. A CPE prefix is the most
  reliable key (`cpe:2.3:o:paloaltonetworks:pan-os`).
- `versions`: deployed versions. Without them every matching CVE is kept with version status
  `unknown` and flagged for review.
- `exposure`, `mission_prevalence`, `public_wellbeing_impact`: SSVC inputs, in CISA wording.

These files describe client infrastructure: keep the repository access restricted accordingly.

## Local LLM

Any OpenAI-compatible server works. The pipeline requests `response_format: json_schema` and
re-validates every answer, so use a server with guided decoding (vLLM or SGLang). For example,
on the RTX PRO 6000:

```bash
vllm serve openai/gpt-oss-120b --port 8000 --max-model-len 32768
```

Then set `llm.enabled: true` and `llm.base_url` in `config/settings.yaml` (or the
`CVE_TRIAGE_LLM_*` environment variables). Check that your server version supports JSON-schema
structured output for the chosen model before enabling it.

What the LLM is allowed to do:

| Task | When | Effect |
|---|---|---|
| `ssvc_inputs` | no CISA ADP data and no CVSS vector | proposes Automatable / Technical Impact, row flagged for review |
| `match_adjudication` | fuzzy product-name match only | keeps (flagged) or drops the candidate |
| `rationale` | every row | French text; rejected if it cites a version, score, CVE id or decision absent from the facts |

If the server is down or answers outside the schema, the run continues with deterministic
behaviour. Advisory text is passed to the model as untrusted data; the model has no tools.

## GitLab CI

`.gitlab-ci.yml` runs lint, tests and profile validation on every push. The `triage` job runs on
a schedule (`TRIAGE_MODE=daily`) or manually (`TRIAGE_MODE=manual`, optional `TRIAGE_CVES`), on a
runner tagged `llm-lan` that reaches the Internet sources (proxy variables) and the LLM endpoint.
Reports are kept as job artifacts for 30 days.

## Sources

| Source | Default URL | Notes |
|---|---|---|
| CVE records | raw.githubusercontent.com/CVEProject/cvelistV5 | includes CISA ADP (SSVC, KEV) containers; can point to an internal mirror or `cveawg.mitre.org/api/cve/{cve_id}` |
| New CVEs | cvelistV5 `deltaLog.json` | used by `--since` |
| KEV | cisa.gov JSON feed | KEV additions since `--since` are always triaged |
| EPSS | api.first.org | batched by 50 |

Responses are cached in `.cache/` (12 h for CVE records, 6 h for feeds).

## Limits and next steps

- Vendor version strings are compared best-effort (`11.1.2-h3`, `2.4.58p1`, `1.0.0rc1` are
  handled); anything undecidable becomes `unknown` and is flagged rather than dropped.
- The CVSS heuristic for Automatable / Technical Impact is coarse; such rows are always flagged.
- No state between runs yet: a CVE that later enters KEV is re-triaged only through the KEV
  addition rule of `--since`. Next: store decisions per client and report changes.
- Next: scanner findings (Tenable, Qualys, Cyberwatch, Trivy) as a second input, sharing the
  same asset model.
