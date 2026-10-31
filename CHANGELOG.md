# Release notes

One entry per release tag, newest first. Each entry says what changed for an operator or an
analyst and, under **Upgrade**, what a tenant must do when it moves to that tag (`ref` and
`A2VM_REF` in its `.gitlab-ci.yml`). Design and reasons: the HLD roadmap (`docs/hld/00-product-strategy.md`
§11) and the LLDs. A release adds its entry here in the same merge request (CLAUDE.md, Releasing).

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
