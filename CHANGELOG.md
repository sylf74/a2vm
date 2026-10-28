# Release notes

One entry per release tag, newest first. Each entry says what changed for an operator or an
analyst and, under **Upgrade**, what a tenant must do when it moves to that tag (`ref` and
`A2VM_REF` in its `.gitlab-ci.yml`). Design and reasons: the HLD roadmap (`docs/hld/00-product-strategy.md`
§11) and the LLDs. A release adds its entry here in the same merge request (CLAUDE.md, Releasing).

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
