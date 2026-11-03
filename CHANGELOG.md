# Release notes

One entry per release tag, newest first. Each entry says what changed for an operator or an
analyst and, under **Upgrade**, what a tenant must do when it moves to that tag (`ref` and
`A2VM_REF` in its `.gitlab-ci.yml`). Design and reasons: the HLD roadmap (`docs/hld/00-product-strategy.md`
§11) and the LLDs. A release adds its entry here in the same merge request (CLAUDE.md, Releasing).

## v0.20.0 — 2026-11-03

Pillar 4 starts: remediation tickets in the ITSM, sent by the tenant's rules or asked for from a
dashboard, and followed until a scan confirms the fix.

- New package and command `dispatch` (pillar 4), image `dispatch`, LLD dispatch-capitalization,
  operating guide `docs/dispatch.md`. The placeholder `remediate/` is removed.
- Tickets: one per asset and fix (`<package> <fixed version>` reported by the scanners), each
  decision in one ticket; the decisions without a known fix of an asset make one ticket. Text from
  templates (no LLM): asset, fix, level, BOD 26-04 due date, the CVEs; linked to the CMDB item of the
  asset (v0.19.0).
- The tenant's rules in `dispatch.yaml` (`dispatch.schema.json`, checked by `validate`): the
  targets (iTop first), what leaves by itself after each run (`automatic`: none, act, act-attend),
  zones left out, what a person may ask; `mode: dry-run` (default) proposes and records, `live`
  sends. No credential in it: `A2VM_DISPATCH_<TARGET>_PASSWORD` (and `_CA`).
- Dispatch service `dispatch serve` (API `dispatch.v1`: process a run, tickets, requests), the
  tickets in the tenant's PostgreSQL (schema `dispatch`) or on its volume; the daily run ends with a
  step `dispatch`. Follow-up: the fixes a scan confirmed are written into the ticket, a ticket with
  none left is resolved, a ticket closed while a scan still sees a vulnerability is reopened; A2VM
  never takes the tool's word for a fix.
- iTop connector: `UserRequest` from a Person (`caller`), optionally to a Team, impact and urgency
  from the level, linked to the CMDB item; comments in the public log; resolve and reopen.
- Requests for remediation (D18): the RSSI versions of the dashboards `remediation` and
  `coverage` (`verdict grafana dashboard NAME --rssi`) link each asset, and every ACT, to a page of
  the dispatch service behind oauth2-proxy, for the groups `A2VM_OIDC_REMEDIATORS`: it shows the
  tickets of the selection, sends them on confirmation (anti-forgery token, same origin), never a
  duplicate, and records who asked.
- Decision service: the decision items carry their `fixes` (`verdict.v1`, added only).
- HLD: D12 names pillar 4; chapter 40 and §6 (contracts `dispatch.v1.yaml`, `dispatch.schema.json`).

**Upgrade**: nothing changes for a tenant without `dispatch.yaml`; move `ref` and `A2VM_REF` to
`v0.20.0`. To use it (`docs/dispatch.md`): in iTop a Person `A2VM` and an account for A2VM; in the
tenant project `dispatch.yaml` in `mode: dry-run`, `A2VM_DISPATCH_<TARGET>_PASSWORD`, and for the
page `A2VM_DISPATCH_HOST`, `A2VM_OIDC_REMEDIATORS` and its redirect URI in Keycloak; import the RSSI
dashboards. No change of the reporting database.

## v0.19.1 — 2026-11-03

The cloud scanner keeps its disk free; two decisions recorded.

- Cloud scanner (`deploy/scanner`): the volume is 90 GB by default (60 GB filled up with the CI
  jobs' images). Each night after the feed update, `cleanup.sh` removes the jobs' stopped
  containers, the images no container has used for 3 days, the runner's cache volumes no container
  uses, the system journal above 200 MB and the package cache; Greenbone's containers, images and
  volumes are never touched. `status.sh` shows the free space and warns under 15 %.
- A changed cloud-init template no longer touches a running scanner (`ignore_changes` on its user
  data): `update-scripts.py` writes the new scripts on it, its secrets and `scanner.env` kept.
- HLD: D17, the vulnerability knowledge shared by every tenant and the watch kept per tenant
  (v0.21.0); D18, the dashboards link to the platform, which acts (requests for remediation in
  v0.20.0). Roadmap updated.

**Upgrade**: nothing for the tenants (they may move `ref` and `A2VM_REF` to `v0.19.1`; no
database change). On a running cloud scanner: `python3 deploy/scanner/update-scripts.py | ssh
root@<scanner> bash`; `terraform plan` then shows no replacement.

## v0.19.0 — 2026-11-02

The tenant's CMDB (iTop) read by A2VM, and the scan coverage of every host against it.

- CMDB as a detection source (`cmdb`, pillar 2): a connector `type: itop` of the collector reads
  every physical and virtual device of iTop (`PhysicalDevice`, `VirtualDevice` and their
  subclasses) over the REST API, `core/get` only: A2VM never writes to the CMDB. Each item with a
  name becomes a host observation with its addresses (management IP, interfaces) and its item
  (class, key, status, criticality, organisation, type). `detect cmdb fetch` for a test.
- Asset context (pillar 3): the CMDB comes after a declaration of the profile and before its
  rules. Business criticality high, medium, low → Mission Prevalence essential, support, minimal;
  owner from the item's first contact, else its organisation. The CMDB is not a scan: it is never
  one of an asset's `scans`.
- Scan coverage of each host (`coverage.json`, `triage.json` `coverage`): `not-in-cmdb`,
  `retired-but-alive`, `not-expected`, `not-scannable`, `never-scanned`, `stale`, `partial`,
  `covered`, against the means of detection its CMDB class expects (profile `coverage:`; defaults:
  servers, virtual machines, hypervisors `openvas` and `trivy|dnf-updateinfo`, PCs `edr`, every
  other class `openvas`; `stale_days` 7). Without a CMDB, every host is judged as in production.
- Decision service: `GET …/coverage` (filters `state`, `gaps`, `class`, `q`), the coverage in the
  summary, the item and coverage state on each asset (`verdict.v1`, added only). Chat tool
  `list_coverage`.
- Reporting database, schema version 4: table `coverage`, views `coverage_facts` and
  `latest_coverage`, coverage totals per run, the item of each asset. Grafana dashboard `coverage`
  (and its French version): one row per host with its class, status, criticality, coverage, the
  means missing and the last date each means saw it.
- `detect cmdb export triage.json --organization <org>`: the hosts scanned but not in the CMDB as
  a CSV for the CSV import of iTop, checked and imported by a person.
- iTop extension `deploy/itop/a2vm-iot-device` (1.0.1): class `IoTDevice` for the connected
  objects with an address (cameras, TVs, media players, energy meters, sensors).
- `docs/cmdb.md` (new), `docs/collectors.md`, `docs/reporting.md`, `docs/operations.md`; LLD
  detection §3.5, triage §5.2, §13, §14.3, §14.6, §15.4, §16.1; HLD chapters 20, 30, roadmap
  (v0.20.0: the dispatch channels, after the CMDB).

**Upgrade**: run `verdict db init` once on the reporting database (schema version 4,
`docs/reporting.md`), then move `ref` and `A2VM_REF` to `v0.19.0` and push; pull the new `detect`
image on the collectors. For the CMDB (`docs/cmdb.md`): a read-only account in iTop, a connector
`itop` on the collector and its timer, the source `cmdb` in `collectors.yaml`. Import the
dashboard `verdict grafana dashboard coverage` (and `--language fr`). Without a CMDB nothing else
changes: the coverage judges every host as in production.

## v0.18.3 — 2026-11-02

Fixes of the cloud scanner found at its first deployment.

- `deploy/scanner`: `status.sh` showed the runner's authentication token. It filtered the token out
  of the runner's own listing, but colour codes around `Token=` defeated the filter. The scripts no
  longer call that listing: they read the registration in `config.toml` and show only its name and
  URL.
- `status.sh` waits 20 s at most for each gvmd query (gvmd holds its lock while it loads the feeds,
  and the script seemed stuck); `gvm-users.sh` prints gvmd's messages only when it fails;
  `register-runner.sh` removes locally a registration already deleted in GitLab (a revoked token).
- `deploy/scanner/README.md`: reading the token without echo (zsh and bash), what to do when a
  token was shown, `ca.pem` not needed with a public certificate on the reverse proxy.

**Upgrade**: move `ref` and `A2VM_REF` to `v0.18.3` and push (nothing changes in the pipelines).
On a scanner built with v0.18.2, rebuild it, or copy the four scripts of `cloud-init.yaml.tftpl`
(`lib.sh`, `gvm-users.sh`, `register-runner.sh`, `status.sh`) to `/opt/a2vm-scanner`. If its
token was shown, delete the runner in GitLab and register a new one (README, "Operate").

## v0.18.2 — 2026-11-02

The cloud scanner deployed by Terraform; OpenVAS collections that survive a silent gvmd; a journal
line per target.

- `deploy/scanner`: Terraform (Scaleway) and cloud-init of the cloud scanner of the external
  projects: Ubuntu 24.04, Greenbone Community Edition in containers with a daily feed update
  (systemd timer), GitLab Runner with the Docker executor and the gvmd socket mounted in its jobs.
  SSH is the only port open inbound. The GMP account `vulnops` (role User) and the web admin's
  password are generated on the instance; the runner gives the GMP account to the jobs, so the
  external project needs no `A2VM_GVM_*` variable. The runner's token is sent over SSH to
  `register-runner.sh` on its standard input, never through Terraform or its state.
  `status.sh` shows the containers, the feeds, the accounts and the runner.
- OpenVAS: `gmp_timeout_seconds` (300) and `gmp_reconnects` (3) in the `openvas` section of
  `targets.yaml`. When gvmd does not answer a read or an idempotent command in time (feed loading,
  large report), the collection opens a new, signed-in connection and makes the same call, up to
  `gmp_reconnects` times for the whole scan. A scan start without an answer is never sent twice,
  and a refusal of gvmd is not retried. Before, one silent answer of 300 s failed the collection
  ("timed out") while gvmd went on scanning.
- Collector agent and `collect` job: one line per target as it ends (`ok` with its findings, or
  `FAIL` with the reason, and the time taken), and a line when each connector starts and ends.
- `docs/openvas.md` §4 and §5, `docs/collectors.md` §3, `docs/operations.md` (known failures),
  LLD detection §3.2, §6, §8.1; HLD roadmap and building blocks.

**Upgrade**: move `ref` and `A2VM_REF` to `v0.18.2` and push; on a collector, pull the new `detect`
image (`docs/operations.md` §5). Nothing else is needed: the new keys of `openvas` have defaults.
For a cloud scanner installed by hand, `deploy/scanner/README.md` ("Moving from a scanner
installed by hand").

## v0.18.1 — 2026-10-31

An asset patched clean stays known; a fix is told from a scan that did not run; remediation KPIs.

- Assets stage: each asset carries `scans`, the latest observation of each source, a scan with no
  finding included (`vulnops.assets/1`, added). `triage.json` lists every asset of the run, a finding
  or not (`a2vm.triage/1`, `assets`, added).
- Decision service and chat: `GET …/assets` and `GET …/assets/{asset}` show every asset of the run;
  an asset with no finding has zero counts and its scans (an asset patched clean was "not in the
  perimeter" before). The summary counts all assets and `assets_with_findings`.
- With the tenant's database: a finding absent from the newest run is closed (fixed) only when its
  asset was scanned again by a source that had seen it, after the finding's last observation;
  otherwise it is `unverified` (scan failed, host off) and opens again with the next run that sees
  it. `GET …/findings/unverified`, `state` and `unverified_since` in `lifecycle` (`verdict.v1`,
  added); chat tool `list_unverified_findings`.
- Reporting database, schema version 3: every asset of a run with its scans, the last observation
  of each finding per source, views `run_pairs`, `finding_closures` (fixed or unverified, days open,
  on time) and `latest_asset_scans`. Grafana dashboard `remediation` (and its French version): fixed
  findings, mean days to fix an ACT, share fixed within the BOD 26-04 due date, gone without a new
  scan, assets not scanned for 7 days, reopened, per day and per level.
- Fix: the French versions of the per-asset and per-CVE dashboards named the English column of
  their bar chart (`xField`): the chart showed no bar.
- Chat: the instructions tell an asset scanned clean from one not scanned, and keep the whole
  answer in the language of the question (a model mixed in another script).
- `docs/operations.md`: operator's manual (where each part runs, usual actions, checks, known
  failures and remedies, upgrades, stopping the cluster).
- HLD roadmap: v0.18.2 (automated cloud scanner, to confirm); v0.19.0 renamed "dispatch channels:
  mail, ITSM, SIRP": remediation tickets in the ITSM (iTop first, then ServiceNow) and, on a
  suspected compromise only, alerts in TheHive (a SIRP, not an ITSM), two flows side by side;
  v0.20.0 the iTop CMDB connector. HLD chapter 40.
- LLD triage §12, §13, §14.4, §15; `docs/reporting.md`.

**Upgrade**: run `verdict db init` once on the reporting database (schema version 3,
`docs/reporting.md`), then move `ref` and `A2VM_REF` to `v0.18.1` and push. Import the dashboard
`verdict grafana dashboard remediation` (and `--language fr`), and import again the French
`assets` and `cves` dashboards.

## v0.18.0 — 2026-10-31

The tenant's PostgreSQL behind the watch, detection and decision services (HLD D15).

- `A2VM_DATABASE=true` on a tenant project: `deploy-k8s` gives the tenant a CloudNativePG cluster in
  its namespace (`a2vm-<tenant>-db`: database and role `app`, no superuser) and `via serve`,
  `detect serve` and `verdict serve` keep their data there instead of their volumes. The operator is
  installed once per Kubernetes cluster (`deploy/cnpg/README.md`); without it the job stops and says
  so. Without the variable nothing changes.
- `a2vm.db`: connection from a file (`A2VM_DB_DSN_FILE`, the cluster's secret) verified against the
  cluster's CA (`A2VM_DB_CA`, `verify-full`), a schema per pillar (`via`, `detect`, `verdict`) created
  at start under an advisory lock, row-level security per tenant on every table (owner included).
- Services on the database: no volume, rolling update, `database.serviceReplicas` replicas; their
  NetworkPolicies open the database (5432) and the DNS only; the database's lets in the three
  services and the operator.
- Decision service: the life of each finding across runs (opened, last seen, closed, reopened, levels).
  `GET …/findings/closed` (findings fixed or no longer detected since a day) and `lifecycle` in
  `GET …/decisions/{id}` (contract `verdict.v1`, added only); chat tool `list_closed_findings`.
- Tests: the tests of the three services run on their files and on PostgreSQL.
- LLD triage §15.8, detection §8.7, intelligence §3.7; HLD roadmap and D15 step 3;
  `docs/kubernetes.md` §5.

**Upgrade**: move `ref` and `A2VM_REF` to `v0.18.0` and push: the services stay on their volumes.
For the database: install the operator once (`deploy/cnpg/README.md`), set `A2VM_DATABASE=true` on
the project and push. The services start empty (what the volumes held is not moved); delete the old
claims (`a2vm-<tenant>-watch`, `-detections`, `-runs`) by hand once satisfied.

## v0.17.3 — 2026-10-31

The rest of A2VM in English (HLD D16), with French labels for the tenants that want them.

- Decisions: the rationale (template and LLM prompt), the reasons of the policy, the review reasons
  (exploitation source, GTI, CVSS heuristic, LLM, fuzzy product match, generic OpenVAS test) and the
  assumptions are written in English. Runs made before keep their texts.
- Client profile: `client.language` (`en` by default, `fr`). The daily report (`report.md`), the HTML
  dashboard and the chat's Word, PowerPoint and CSV documents take their labels from the catalogue
  `verdict.i18n` in that language; the texts of the decisions stay in English, as validated.
- `triage.json` (`a2vm.triage/1`) carries `client.language`; the decision service gives it in the
  `run` of its answers (`verdict.v1`, `RunRef.language`). Fields added only.
- Grafana: a French version of each dashboard (`<name>.fr.json`, uid `<uid>-fr`), built by code from
  the English one; `verdict grafana dashboard NAME --language fr`.
- Watch sources named in English (e.g. `CERT-FR — alerts`); the count of consecutive failures of a
  renamed source starts again from zero.
- LLD triage §2.5, §13.3, §15.2, §16.6; HLD D16, chapter 30 and roadmap; `docs/reporting.md`.

**Upgrade**: move `ref` and `A2VM_REF` to `v0.17.3` and push. For French deliverables, add
`language: fr` under `client:` in `client.yaml`. For French Grafana dashboards, import
`verdict grafana dashboard NAME --language fr` once per dashboard (they sit next to the English ones).

## v0.17.2 — 2026-10-31

Fix of the chat with the analysts' sign-in.

- Chat: `BYPASS_MODEL_ACCESS_CONTROL=true`. An analyst signed in through the provider (role `user`)
  saw no model since v0.17.0: Open WebUI shows a user only the models granted to them; the tenant's
  model is the only one configured. Meant for v0.17.1, tagged without it.

**Upgrade**: move `ref` and `A2VM_REF` to `v0.17.2` and push.

## v0.17.1 — 2026-10-30

English reference and translations of the alerts (HLD D16).

- The watch writes the alert sheet in English: headings and labels from a catalogue per language
  (`via.alert.i18n`: English, French), the title, main impact and description by the LLM in English;
  the analysts' mail and the review page are in English.
- `contacts.yaml`: `language` per contact (ISO 639-1, default `en`).
- Review page: a validator enriches the English reference, chooses the recipients (with their
  language), checks and corrects the translation made for each language, then validates. Enriching
  the reference outdates its translations. Status `translating`; events `translation-requested`,
  `translated`, `translation-failed`, `translation-edited`.
- The sender translates with the tenant's LLM (`via.alert.translate`): same structure, every CVE id
  and URL kept, no version, score or CVE id added, headings and table header from the catalogue;
  refused otherwise, with the reason, and a validator can write the translation. It mails each
  language its validated version, with its Word file in that language: templates
  `templates/alert.<lang>.docx` (else the client's `templates/alert.docx`, else the neutral template
  of the language: `alert.en.docx`, `alert.fr.docx`).
- `a2vm.ssvc.remediation_delay` in English by default (`lang="fr"` for French).
- Contract `via.v1`: the translations' calls, the new status and events (added only).
- LLD intelligence §3.5 and §3.9, HLD D16 and chapter 10, `docs/alerts.md`, `docs/alert-word.md`,
  `docs/sign-in.md`.

**Upgrade**: move `ref` and `A2VM_REF` to `v0.17.1`. The sheets are now in English: give
`language: fr` to the contacts who read French, and, for a French Word layout, name the client's
template `templates/alert.fr.docx` (a `templates/alert.docx` serves every language). Sending through
GitLab (`send-alerts`) sends the English reference to everyone.

## v0.17.0 — 2026-10-30

The analysts sign in with the tenant's identity provider; the alerts are validated on a page, no
longer in GitLab.

- Sign-in (OIDC; Keycloak described in `docs/sign-in.md`, any provider with discovery): the chat
  (Open WebUI: role from the groups claim, members of the readers' and validators' groups only,
  optional admins' group, no account joined by e-mail, PKCE) and the review page.
- Review page of the alerts on `via serve` (port 8081), behind oauth2-proxy v7.15.5 (allowed
  groups, PKCE, cookie key made by `deploy-k8s`); reached from the proxy only. Readers read; a
  validator corrects the sheet (no CVE the alert does not concern), validates it or dismisses it.
  Forms signed per analyst and alert, same origin only, no script on the page. Journal events
  `edited`, `validated`, `dismissed` with `by`; statuses `validated` and `dismissed`.
- Sender (`via service send --validated --every 30`, one replica): mails the validated alerts with
  their corrected sheet, once; a failure waits for a new validation. `via serve` and the page hold
  no mail secret and no Kubernetes right.
- The analysts' mail links to the alert on the page (`A2VM_REVIEW_URL`); without the page, to the
  prefilled pipeline as in v0.16.0.
- Contract `via.v1`: `GET …/alerts/{alert}/edit`, the new statuses and events (fields added).
- Chat: `get_alert` gives the corrected sheet, `list_alerts` the new statuses.
- `deploy-k8s`: `A2VM_OIDC_*` and `A2VM_ALERTS_HOST` (`deploy/chat/sign_in_values.py`), keys
  `oidc-client-secret`, `oidc-ca`, `oidc-cookie-secret`, `review-key` in the Secret.
- `docs/sign-in.md`; LLD intelligence §3.8, LLD triage §16.4 (the Open WebUI settings of the
  sign-in), HLD chapter 10 and D15, `docs/kubernetes.md`, `docs/chat.md`, `docs/alerts.md`.

**Upgrade**: move `ref` and `A2VM_REF` to `v0.17.0`; nothing changes without `A2VM_OIDC_ISSUER`.
To sign in with the provider: create the client (`docs/sign-in.md` §1), set the `A2VM_OIDC_*`
variables and, with `A2VM_RUN_MODE: kubernetes`, `A2VM_ALERTS_HOST`, then push.

## v0.16.2 — 2026-10-30

The watch runs with via and a2vm only; the interfaces between pillars are documented and checked.

- The matching of declared assets (`detect inventory`'s code) is `a2vm.declared`, with
  `a2vm.matching` and `a2vm.versions`; the CISA SSVC tables and the BOD 26-04 delay are
  `a2vm.ssvc` (data files in `a2vm/src/a2vm/data/`). Owned by pillars 2 and 3, run by the watch
  too. The extension points `a2vm.extensions` (`a2vm.asset_matcher`, `a2vm.remediation_timeline`)
  are removed, and each image holds one pillar again: the via image no longer carries detect and
  verdict.
- The watch's recommended delay takes Automatable and Technical Impact from the CISA ADP, else the
  CVSS vector, else `policy.unknown_inputs` (no LLM estimate in the watch; the triage still makes
  one).
- A test runs the watch with detect and verdict absent, as in its image.
- Each LLD has a §1.1 *Interfaces with the other pillars* (provided, consumed, contract, access,
  behaviour when the other side is missing) and HLD §6 a table of every interface;
  `tests/test_interfaces.py` checks that every JSON Schema and OpenAPI file is in both. Schema ids
  named as written (`vulnops.records/1`, `vulnops.detection/1`). D12 reworded.
- Roadmap: sign-in through the tenant's identity provider (OIDC) with the review page of the
  alerts in v0.17.0, PostgreSQL in v0.18.0.

**Upgrade**: move `ref` and `A2VM_REF` to `v0.16.2` and push; nothing else.

## v0.16.1 — 2026-10-30

Fix of the watch on Kubernetes.

- The via image now also holds detect and verdict. The watch matches the alerts to the client's
  assets with detect (`a2vm.asset_matcher`) and dates their remediation with verdict
  (`a2vm.remediation_timeline`); without them, every passage after the baseline stopped with
  `no installed pillar offers a2vm.asset_matcher (install detect)`. The image build checks both
  are there.
- LLD intelligence §3.7.

**Upgrade**: move `ref` and `A2VM_REF` to `v0.16.1` and push. A tenant in `A2VM_RUN_MODE:
kubernetes` loses no alert: the failed passages kept the state, the first passage with v0.16.1
sees every item since the baseline.

## v0.16.0 — 2026-10-29

The watch on Kubernetes: a tenant no longer needs GitLab to run, only to deploy and validate.

- `A2VM_RUN_MODE` in the tenant's `.gitlab-ci.yml`: `gitlab` (default, as before) or `kubernetes`,
  where the scheduled pipelines no longer run the daily jobs nor the watch, and `deploy-k8s`
  deploys the watch beside the daily run.
- `via serve`: the watch service of the tenant (contract `via.v1`), the only writer of the watch's
  state, the last daily inventory, the alerts with their sheets and their journal; roles `run`
  (the tenant's jobs) and `read` (the chat's tools); sends nothing.
- The watch as a CronJob every 10 minutes (`via service watch`): state and inventory from the
  service, the same `via watch`, alerts, events and new state back. The daily run pushes its
  inventory at a new step `inventory` (`via service push-inventory`).
- Validation: the analysts' mail links to a prefilled *Run pipeline* (`A2VM_JOB=send`,
  `A2VM_SEND_ONLY=<alert id>`); the job `send-alerts-k8s` starts a send Job in the namespace
  (`via service send`, the same `via send`, the edits of the branch), which journals what it sent;
  an alert is never sent twice by mistake.
- Chat: `list_alerts` and `get_alert` read the watch service.
- `deploy-k8s`: run and read tokens of the watch service (Secret keys `via-run-token`,
  `via-read-token`, digests in `a2vm-via`), `contacts.yaml`, `watch-sources.yaml`, the Word
  template (ConfigMap `a2vm-alert-template`), the mail settings (`smtp-password`,
  `graph-client-secret` in the Secret, the others as settings).
- LLD intelligence §3.7, HLD chapter 10 and D15 migration, `docs/kubernetes.md` §4,
  `docs/alerts.md`, `docs/chat.md`.

**Upgrade**: nothing changes with `A2VM_RUN_MODE: gitlab`. To move a tenant: set
`A2VM_RUN_MODE: kubernetes` in its `.gitlab-ci.yml` and push; its first watch passage records the
baseline. A profile with `alerts.attach: [pdf]` keeps the GitLab mode (no LibreOffice in the via image).

## v0.15.2 — 2026-10-28

The analysts' daily questions in the chat.

- What changed: `GET changes` on the decision service and the tool `what_changed`: decisions new,
  gone or at another level since the run before (or a given run), each with why, from the facts of
  both runs (first detected by a source, CVE published or updated, added to KEV, EPSS, exposure,
  SSVC inputs).
- Dates: the records keep `updated` (`dateUpdated`) and `epss_date`; every decision carries
  `cve_published`, `cve_updated`, `kev_date_added`, `kev_due_date`, `epss_date` (fields added to
  `a2vm.vulnerability_records/1` and `a2vm.triage/1`); lists show `first_seen` and `cve_updated`.
- Fix plan: `GET assets/{asset}/fixes` and the tool `get_fix_plan`: the decisions of an asset
  grouped by the fix that clears them, the one that clears most ACT first.
- Due dates: filters `due_before` and `overdue` on the decisions (and the documents).
- Concerned or not: `cves/{cve}` says `concerned`, lists the assets that have the product outside
  the vulnerable range (`not_affected`), and a 404 says no asset is concerned.
- Instructions of the model: when no tool answers, say so, never guess causes, dates or figures.
- Contract `verdict.v1` (two calls, two filters), LLD triage §15 and §16.1, LLD intelligence §2.3,
  HLD §6, `docs/chat.md` §8.

**Upgrade**: move the tenant to v0.15.2 and push. The dates appear with the next daily run;
`what_changed` answers once the decision service holds two runs.

## v0.15.1 — 2026-10-28

The analysts' chat, after its first use on a tenant.

- Assets found as people name them: by id (`host:web01.example.org`), host name
  (`web01.example.org`) or short name (`web01`), any case, in the decision service's filter `asset`
  and in `assets/{asset}`. The tool server decodes the path parameters the chat encodes (an asset id
  with `:` or `/` was refused).
- Documents: `export_decisions` builds a Word (A4 landscape), PowerPoint (16:9) or CSV document from
  the data (run, filters, counts, table, explanation of the most urgent decisions); the chat answers
  a download link on its own address, valid one hour (`/a2vm/exports/…`, routed to the tool server,
  token never logged). verdict depends on `python-docx` and `python-pptx`.
- Retention: a second container of the chat's pod (`verdict chat-retention`) deletes every hour the
  chats unchanged for `A2VM_CHAT_RETENTION_DAYS` days (default 30, 0 keeps them), as Open WebUI
  deletes a chat.
- Instructions of the model: look an asset up with `list_assets` before saying it has nothing; the
  only link allowed is a document's; every answer ends with `Source : run <id> du <date>`.
- LLD triage §15.4 and §16 (16.6 documents, 16.7 retention), `docs/chat.md` §7.

**Upgrade**: move the tenant to v0.15.1 and push; nothing else (`A2VM_CHAT_RETENTION_DAYS` to keep
chats longer than 30 days). Chats older than 30 days are deleted within the hour after the upgrade.

## v0.15.0 — 2026-10-28

Conversational search for analysts (HLD §8), all in the tenant's namespace; the model stays on the
tenant's approved LLM endpoints outside the cluster.

- `verdict tools`: read-only OpenAPI tool server on the decision service for the model of the
  chat: run summary, decisions with filters, one decision explained, one CVE, assets, runs. Answers
  of about 2,000 tokens at most that name their run; vendor links and images removed. It holds the
  decision service's read token; the chat has a token of its own (LLD triage §16).
- Chart: `chat.enabled` deploys Open WebUI (v0.12.4) and the tool server, configured from the
  values only: the tenant's model and endpoints only, no web search, no code execution, no file
  upload, offline, Content-Security-Policy, sign-up closed (first admin from the Secret),
  NetworkPolicies to the tool server, the LLM endpoints and the DNS only.
- `deploy-k8s`: with `A2VM_CHAT_HOST`, makes the chat's secrets once (Secret keys
  `chat-secret-key`, `chat-admin-password`, `chat-tools-token`; digest in the Secret `a2vm-chat`)
  and its values (`deploy/chat/chat_values.py`: endpoints resolved for the NetworkPolicy).
- Several LLM endpoints per tenant: `A2VM_LLM_BASE_URL` (or `llm.base_url`) takes a comma-separated
  list. The daily run moves to the next endpoint when one is down and stays there; the chat goes
  through an LLM gateway in the namespace (nginx: round robin, a failed endpoint left out and the
  request sent to the next), since Open WebUI uses one endpoint per model.
- Decision service (v0.14.0 follow-ups): successful probes no longer logged (also `detect serve`),
  memory request and limit by default (256 Mi, 1 Gi), the read command of `docs/kubernetes.md`
  mounts the token instead of passing it on the command line.
- `docs/chat.md`: deployment, first sign-in, checks, several endpoints, what is closed, limits.

**Upgrade**: for the chat, serve the model with tool calling (vLLM: `--enable-auto-tool-choice
--tool-call-parser hermes`), set `A2VM_CHAT_HOST` (and `A2VM_CHAT_ALLOW`) on the tenant project
and push; then sign in as the first admin and create the analysts' accounts (`docs/chat.md` §3).
Without `A2VM_CHAT_HOST`, nothing changes.

## v0.14.0 — 2026-10-28

D15 step 3, read side first: the decision service of each tenant.

- `verdict serve`: the latest runs of the tenant (decisions with their rationale and SSVC inputs,
  assets, CVEs) behind a read API, contract `a2vm/schemas/openapi/verdict.v1.yaml`: summary,
  decisions filtered and paged, one decision in full, one CVE, assets. Runs kept as files on the
  service's volume (the last 7 by default) until PostgreSQL.
- `verdict push`: the daily run pushes its triage (`a2vm.triage/1`, new identifier of
  `triage.json`) to the service at the `publish` step, before the reporting database.
- Chart: `verdict.enabled` deploys the service (Deployment, Service, volume, NetworkPolicy: from the
  tenant's daily run and pods labelled `a2vm.io/verdict-reader=true` only, no egress); no ingress
  (read inside the cluster). A failed push is a warning: the next run pushes again.
- `deploy-k8s`: makes the publish and read tokens of the service once and keeps them (Secret keys
  `verdict-publish-token`, `verdict-read-token`), their digests in the Secret `a2vm-verdict`.
- Release notes in `CHANGELOG.md`, from v0.4.0; LLD triage §15, `docs/kubernetes.md`.

**Upgrade**: nothing to do; the service is deployed with the tenant (`A2VM_VERDICT_SERVICE=false`
to leave it out). The first daily run after the upgrade fills it.

## v0.13.3 — 2026-10-28

- Large detections (100 MB and more): a retry is answered from its idempotency key before any
  decompression or validation; the gzip body is stored as received; the agent and `detect fetch`
  wait 10 minutes (`timeout_seconds`, `--timeout-seconds`); each push logs its size and time.
- One daily run at a time on a tenant's volume: `collect` takes a lock, released at the end or
  when a step fails; a run started by hand next to another one stops.
- HLD: conversational search for analysts (§8) and the reordered roadmap.

**Upgrade**: change the image tag of the collectors' systemd unit to the new release.

## v0.13.2 — 2026-10-27

- `deploy/collector/install-collector.sh`: installs a collector on its VM (scan key, targets,
  GMP account on the scanner host, `collector.yaml`, image, systemd units), can be run again.

## v0.13.1 — 2026-10-26

- Push endpoint behind Traefik: allow-list as an `ipAllowList` Middleware
  (`A2VM_INTAKE_INGRESS_CONTROLLER=traefik`); certificate from a cert-manager issuer
  (`A2VM_INTAKE_CLUSTER_ISSUER`).
- Collector guide: OpenVAS on the collector, the two CAs, end-to-end check.

**Upgrade**: behind a LoadBalancer Service, the ingress controller needs
`externalTrafficPolicy: Local` for the allow-list to see the collectors' addresses.

## v0.13.0 — 2026-10-24

D15 step 2: collectors near the networks push to the detection service of the tenant.

- `detect serve` (API `detect.v1`), `detect agent` (connectors `targets`, `file-import`, spool),
  `detect fetch`; `detect collectors` checks `collectors.yaml` in `validate`.
- Chart: detection service, push endpoint published to the collectors' addresses only;
  `collect.mode: intake` makes the daily run read the service.
- `deploy-k8s`: token digests from `A2VM_COLLECTOR_TOKEN_<ID>`, read token of the daily run.

**Upgrade**: optional. A tenant without `collectors.yaml` is unchanged; with one, declare the
collectors, set their tokens and install them (`docs/collectors.md`).

## v0.12.1 — 2026-10-24

- Pillar images built with Buildah on a dedicated, protected build runner (shell executor,
  rootless); the tenants' runner stays unprivileged.

## v0.12.0 — 2026-10-24

D15 step 1: the daily run of a tenant on Kubernetes.

- One container image per pillar, built at every tag (`images`).
- Chart `a2vm-tenant`: the daily run as a CronJob, one container per step; deployed from the
  tenant project by `deploy-k8s` through the GitLab agent (`docs/kubernetes.md`).

## v0.11.7 — 2026-10-23

- Decision chain and the CISA Coordinator and BOD 26-04 trees drawn in the triage LLD from the
  SSVC tables; documentation published to a product project on every tag; code project path and
  runner tags as group variables; fictitious tenant `examples/demo-industrie`; `CLAUDE.md`.

## v0.11.6 — 2026-10-22

- Restitution in pillar 3 (`verdict publish`, `verdict db`, `verdict grafana`); dashboards "which
  assets to fix first" and "which CVEs to fix first"; each decision carries its CVSS rating, fix
  availability, product type and detection sources; LLDs of pillars 1 and 2.

**Upgrade**: reporting database schema version 2: `verdict db init` once (`docs/reporting.md`).

## v0.11.5 — 2026-10-22

- Reporting database (PostgreSQL) filled by a `publish` job from each run's dataset, with history
  and a reading role per tenant; Grafana dashboard; portal deployed as code (Terraform,
  cloud-init). In production GitLab holds and deploys code and configuration only (D3).

**Upgrade**: to publish, create the database (`verdict db init`) and set `A2VM_REPORTING_DSN`.

## v0.11.4 — 2026-10-21

- Exposure gaps in the report and the dataset; alert sheet as a Word file from a template per
  client, sent as Word or as a PDF; analysts edit a sheet in the client project before sending.

## v0.11.3 — 2026-10-21

- Reporting dataset (`reporting.json`); analysts choose which alerts are sent (`A2VM_SEND_ONLY`);
  alert journal and trace of the mails sent; mail test job; `validate` checks the include ref
  against `A2VM_REF`; a watch source fails only after several runs in a row; CISA advisories as
  CSAF; external detection read with a project access token.

## v0.11.2 — 2026-10-21

- External detection pulled by the tenant project and joined through `published` endpoints;
  the watch reads the last daily inventory and the alert sheet lists the assets concerned; fuzzy
  product match by the LLM is a proposal only.

## v0.11.1 — 2026-10-20

- CI/CD variables renamed `VULNOPS_*` → `A2VM_*`; client alert mails titled `[CERT Alert]`.

**Upgrade**: rename the variables; the old names are still read, with a warning.

## v0.11.0 — 2026-10-20

- Project renamed A2VM: GitLab project `vulnops/a2vm`, contract package and command `a2vm`; the
  group, CI/CD variables, exchange-file identifiers and scan accounts unchanged.

**Upgrade**: include `templates/client-pipeline.yml` from `vulnops/a2vm`.

## v0.10.0 — 2026-10-20

- Repository organised by pillar: common contract, `via`, `detect`, `verdict`, each with its own
  command; no functional change.

## v0.9.0 — 2026-10-20

- Exposure model: SSVC System Exposure values, with their source and zone.
- HLD and LLD in the repository: product strategy, one chapter per pillar, verdict LLD.
- Licence: AGPL withdrawn, all rights reserved pending a licensing decision.

## v0.8.6 — 2026-10-18

- OpenVAS: generic multi-CVE tests flagged for review, CVSS v2 fallback, rejected CVE ids ignored.

## v0.8.5 — 2026-10-18

- OpenVAS: a recent finished scan is collected instead of starting a new one.

## v0.8.4 — 2026-10-17

- Pipeline template: collection on a dedicated runner; GitLab behind a client-certificate proxy.

## v0.8.3 — 2026-10-17

- Pipeline template: the runner's CA file trusted when GitLab uses a private CA.

## v0.8.2 — 2026-10-17

- CI: the `openvas` extra installed so that the OpenVAS tests find lxml.

## v0.8.1 — 2026-10-17

- OpenVAS connector: network scans over GMP and import of reports.

## v0.8.0 — 2026-10-12

- Google Threat Intelligence connector.

## v0.7.0 — 2026-10-12

- Catalogue of watch sources: institutional, vendors, research (RSS, CSAF, CNA).

## v0.6.2 — 2026-10-12

- Client contacts with roles and alert levels (`contacts.yaml`).

## v0.6.1 — 2026-10-12

- Alert mail per client, also through Microsoft Graph.

## v0.6.0 — 2026-10-12

- Watch mode (CERT-FR, KEV, critical CVEs → alerts validated before they reach the client) and
  HTML dashboard.

## v0.5.0 — 2026-10-11

- Triage at scan scale: CVSS from the scanners, report by CVE, one LLM rationale per CVE.

## v0.4.2 — 2026-10-11

- Real scan volumes: smaller artifacts, LLM budget, intelligence collected in parallel.

## v0.4.1 — 2026-10-11

- Client pipeline: scan key normalised and checked, incomplete collection flagged.

## v0.4.0 — 2026-10-11

- Multi-tenant layout: one GitLab project per client; detection connectors, asset inventory stage
  and findings v2.
