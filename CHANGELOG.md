# Release notes

One entry per release tag, newest first. Each entry says what changed for an operator or an
analyst and, under **Upgrade**, what a tenant must do when it moves to that tag (`ref` and
`A2VM_REF` in its `.gitlab-ci.yml`). Design and reasons: the HLD roadmap (`docs/hld/00-product-strategy.md`
§11) and the LLDs. A release adds its entry here in the same merge request (CLAUDE.md, Releasing).

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
