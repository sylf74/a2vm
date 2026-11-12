# Release notes

One entry per release tag, newest first. Each entry says what changed for an operator or an
analyst and, under **Upgrade**, what a tenant must do when it moves to that tag (`ref` and
`A2VM_REF` in its `.gitlab-ci.yml`). Design and reasons: the HLD roadmap (`docs/hld/00-product-strategy.md`
§11) and the LLDs. A release adds its entry here in the same merge request (CLAUDE.md, Releasing).

## v0.23.12 — 2026-11-12

No library of a tenant leaves it for OSV any more: the libraries are matched at home, against a copy
of OSV.

- **`A2VM_OSV_MODE=offline`, the default**: the daily run matches the libraries (images, SBOMs)
  against an index of OSV per language ecosystem (PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet,
  Packagist): the records with a CVE, the versions affected and the ranges (`a2vm.osvdb`). In
  v0.23.11 every `purl@version` went to api.osv.dev: the inventory of the tenant, at Google.
- **The shared intelligence service builds the indexes** from OSV's public archives every 6 hours
  (`intel.serve.osvEveryHours`), only when an archive changed, and serves them to every tenant
  (`GET /v1/osv/<ecosystem>`, 304 when unchanged). It learns nothing of the tenants' libraries: all
  read every index. A tenant without the shared service reads the archives itself
  (osv-vulnerabilities.storage.googleapis.com). Yesterday's index serves when the source cannot be
  reached (a warning, exit 3).
- `A2VM_OSV_MODE=api` keeps the behaviour of v0.23.11, for a test or a tenant that accepts it in
  writing; the pages of an answer are now followed (a package with many vulnerabilities lost some).
  `off`, or `A2VM_OSV_ENABLED=false`: nothing.
- The relay of the sources lists `osv-vulnerabilities.storage.googleapis.com` (`deploy/relay`).
- Not checked against the real archives from here (no access): the shared service's log gives, at
  its first build, one line per ecosystem, `osv <ecosystem>: <n> records, <m> with a CVE`.

**Upgrade**:

1. The watch team's release (tenant via) first, to `v0.23.12`: the shared service builds the
   indexes ten seconds after it starts (a few minutes: npm's archive is the largest). Its volume
   (`intel.serve.storage.size`, 1Gi) holds the archive being read: 2Gi if the log says no space
   left. With a relay: add `osv-vulnerabilities.storage.googleapis.com` to `A2VM_RELAY_HOSTS` and
   to the relay's `hosts`, then `terraform apply`.
2. The other tenants to `v0.23.12`. Nothing to set: `offline` is the default. A tenant that had
   `A2VM_OSV_ENABLED=false` for confidentiality can remove it.

## v0.23.11 — 2026-11-12

The libraries of the images and of the SBOMs are checked every day against OSV; a library updated
on disk but still in memory says a restart is needed; the tenant chooses whether the chat forwards
the user.

- **Images**: Trivy lists every library it finds in an image (`--list-all-pkgs`); the image's
  observation keeps them (`type: library`, with their `purl`) and the image's digest.
- **SBOMs**: a connector `sbom` of the collector reads the CycloneDX and SPDX files (JSON) of a
  directory, one asset per file (`docs/collectors.md`); by hand `detect sbom read --config`.
- **OSV**: `detect osv`, every daily run after the collection, asks OSV (api.osv.dev, through the
  proxy) which vulnerabilities concern each library; those with a CVE become findings of source
  `osv`, decided like any finding. The hosts are not touched again. OSV unreachable: a warning, the
  run goes on. `A2VM_OSV_ENABLED=false` skips it (LLD detection §3.10).
- **In memory**: after the packages of a host, the collector reads `/proc/<pid>/maps` over SSH; a
  shared library deleted on disk and still mapped by a process is a component `in-memory` with its
  processes (`812 nginx`). The log says `WARN <host> [loaded]: … restart needed`. Without root, only
  the processes of the SSH user are read.
- **Forwarded user**: `chat.forwardUserInfo` (`A2VM_CHAT_FORWARD_USER_INFO`, default `true`) sets
  `ENABLE_FORWARD_USER_INFO_HEADERS`. These headers go to the LLM endpoints too: `false` for a SaaS
  LLM; the journal then reads « chat (user not forwarded) » (`docs/llm.md` §4).
- Roadmap: the image's scan skipped when its digest is unchanged, every loaded library tied to its
  package, and the levels of proof of the libraries move to « Later (D20) ».

**Upgrade**:

1. Move `ref` and `A2VM_REF` of the tenants to `v0.23.11`. The daily run reaches api.osv.dev
   (HTTPS, through the proxy): else set `A2VM_OSV_ENABLED=false`.
2. A tenant whose LLM is a SaaS: `A2VM_CHAT_FORWARD_USER_INFO=false`, then `deploy-k8s`.
3. The collectors to `detect:v0.23.11`: the images' libraries and the libraries in memory appear
   from their next run. An `sbom` connector, if wanted: `collector.yaml` and `sbom` in the
   collector's `sources` (`collectors.yaml`).

## v0.23.10 — 2026-11-11

The chat acts, with a person's confirmation; it knows the next scans; and every action is in an
audit journal imputable to an author.

- **Actions**: « lance une synchro CMDB », « relance le scan OpenVAS » (`request_connector_run`).
  The chat prepares a request, never runs it: a validator confirms or cancels it on the review page
  (new page « Actions », signed in by OIDC); the collector takes it at its next poll, within five
  minutes, runs the connector and says how it went (`list_actions`: proposed, confirmed, taken,
  done, failed, cancelled, expired). A request not confirmed within the hour expires. One action
  for now, `run-connector`. Actions need the tenant's database (LLD triage §16.10).
- **The poll of the collectors**: `detect agent poll`, every 5 minutes by its own timer
  (`a2vm-collector-poll.timer`), reports the connectors' timers and carries out the confirmed
  requests. It only connects out (`POST /v1/tenants/<tenant>/poll`, published by the intake's
  ingress beside the push). The install script writes its units; by hand: `docs/collectors.md`.
- **The next scans**: `list_collectors` gives each connector's next and last run; « quand les
  décisions seront-elles mises à jour ? »: `get_platform_status` gives the daily run's next start
  (from its CronJob schedule).
- **Audit journal** (`get_audit`): every tool call of the chat with who asked (Open WebUI forwards
  the user: `ENABLE_FORWARD_USER_INFO_HEADERS`), every step of an action, every validation on the
  review page (alerts edited, recipients chosen, validated or dismissed; applications), every push
  of a collector. In the tenant's database (`audit.entries`, kept 365 days), else a file per
  service, and always a log line.
- The tool server reaches the tenant's database and the detection service (network policies); the
  latter was missing in v0.23.9: `list_collectors` could not reach the service.
- 11 questions added to `tests/chat-questions.yaml` and to `docs/chat-questions.md`.
- Roadmap: the libraries in memory and the SBOMs move to v0.23.11.

**Upgrade**:

1. Move `ref` and `A2VM_REF` of the tenants to `v0.23.10` (`deploy-k8s`: the tool server gets the
   database, the review page its « Actions »).
2. Each collector: the image `detect:v0.23.10`, then the poll units (`docs/collectors.md`, *The
   poll*), or the install script again.
3. In Open WebUI, ask « Lance une synchro CMDB », confirm on the review page, then « Ma synchro CMDB
   est-elle terminée ? » and « Qui a lancé la synchro CMDB ? ».

## v0.23.9 — 2026-11-11

The chat knows the platform.

- **`get_platform_status`**: the version of each service of the tenant (decision, watch, detection,
  the tool server), the version that made the latest daily run, when it ended, its LLM and what it
  cost (`llm_usage`), the collectors late or refused. « Quelle version d'A2VM tourne ? », « le run
  de ce matin est-il fini ? », « tout est-il à jour ? ».
- **`list_collectors`**: each collector and source, its last push, the age of its data, late or
  refused, the connector that pushed and the agent's version. « Quels collecteurs ? », « quand
  OpenVAS a-t-il remonté ? », « quelle version sur le collecteur ? ».
- The agent sends its version and the connector's name with each push (`X-A2VM-Agent`,
  `X-A2VM-Connector`); the detection service keeps the last ones in memory and answers them on
  `collectors` and the new `status`. The decision service has a `status` too; the watch's `status`
  names its version; the run records `a2vm_version`.
- The tool server reads the detection service when `intake.enabled` (the token `detect-read-token`
  of the tenant's secret, already there for the daily run).
- 7 questions added to `tests/chat-questions.yaml`, and **`docs/chat-questions.md`**: the questions
  the analysts can ask, by theme, with the tool that answers each, generated from that file
  (`python scripts/make_chat_guide.py --write`; the tests check it is up to date).
- Roadmap: the libraries in memory and the SBOMs move to v0.23.10.

**Upgrade**:

1. Move `ref` and `A2VM_REF` of the tenants to `v0.23.9`.
2. The collectors to `detect:v0.23.9`: the agent's version and the connector appear from their next
   push (until then, the collector's pushes are listed without them).

## v0.23.8 — 2026-11-11

The tenant chooses its LLM. A client may refuse a model of some origin: each family takes the
level of reasoning its own way, and A2VM now sends it that way.

- **`llm.family`** (`A2VM_LLM_FAMILY`): qwen3, gemma, gpt-oss, mistral or generic; empty, it is
  found from the model's name (`openai/gpt-oss-20b` -> gpt-oss).
- **`llm.reasoning`** (`A2VM_LLM_REASONING`): off, low, medium or high, sent as
  `chat_template_kwargs.enable_thinking` for Qwen3 and Gemma 4, `reasoning_effort` for gpt-oss
  (low at least) and Mistral Small 4 (none or high), nothing for the others. `A2VM_LLM_THINKING`
  (v0.23.7) still works alone; `A2VM_LLM_REASONING` wins when both are set.
- **`docs/llm.md`**: the settings, the models known to work (gpt-oss-20b on a 16 GiB GPU,
  gpt-oss-120b, Mistral Small 4 and Gemma 4 on a DGX Spark), their vLLM flags for the chat's tools,
  and how to change the model and check the result.
- The job log and the run's `llm_usage` name the family and the level.
- Roadmap: the libraries in memory and the SBOMs move to v0.23.9.

**Upgrade**:

1. Move `ref` and `A2VM_REF` of the tenants to `v0.23.8`.
2. To change the model: `A2VM_LLM_MODEL` (and `A2VM_LLM_BASE_URL`), `A2VM_LLM_REASONING=off` on
   the group or the tenant project, then push the tenant project (`docs/llm.md` §3).

## v0.23.7 — 2026-11-11

A lighter triage. In the lab the daily triage kept the GPU busy for about 3 hours, for decisions
mostly TRACK and 15 000 rows asking for a review.

- **Thinking off** (`llm.thinking`, CI/CD variable `A2VM_LLM_THINKING`): `off` asks vLLM to answer
  without the reasoning a model such as Qwen3 writes before its JSON; `on` asks for it; empty sends
  nothing, as before (other servers may refuse the field).
- **Answers kept from one run to the next** (`llm.cache_file`, on Kubernetes `/data/llm-cache.json`
  on the working volume, on by default): a question asked yesterday (same model, prompts, schema) is
  not asked again; an answer not used for 30 days is forgotten. The EPSS of the rationale facts is
  rounded to 2 decimals, so that its daily drift does not make a new question.
- **Review where it matters** (policy `review: decisive`, the default): a row asks an analyst only
  when the values its uncertain inputs could take (estimated automatable or technical impact,
  exploitation without assessment, assumed exposure or mission) give another decision. The reasons
  stay in the row as notes. `review: all` keeps the earlier rule.
- **What the LLM cost**: `llm_usage` in the run (questions, answers from the cache, tokens, seconds,
  thinking), in the chat's run summary and in the job log
  (`LLM: <n> questions, <m> from the cache, …`). `docs/operations.md` §2 says how to read it.
- Roadmap: the libraries in memory and the SBOMs move to v0.23.8.

**Upgrade**:

1. Move `ref` and `A2VM_REF` of the tenants to `v0.23.7`.
2. A reasoning model served by vLLM (Qwen3): set `A2VM_LLM_THINKING` to `off` on the group (or the
   tenant project), then push the tenant project so that `deploy-k8s` passes it to the cluster.
3. The first run fills the cache; from the second, `from_cache` should be close to `questions`.
   The number of rows to review drops: those left are the ones whose doubt changes the decision.

## v0.23.6 — 2026-11-10

D20: the appliances and network devices, by their firmware.

- **Connector `snmp` of the collector** (`docs/appliances.md`, LLD detection §3.9), read only: SNMPv3
  `authPriv` by default (SHA-2, AES), SNMPv2c for old devices; GET of sysDescr, sysObjectID, sysName
  and, for Fortinet, Palo Alto Networks and MikroTik, their version object. Targets: addresses, names
  or networks (4096 addresses at most), less `exclude`. One host per device that answers (address,
  name from sysName, OS `<vendor> <product> <version>`), its firmware as a component of type
  `firmware` with the CPE of its family: Cisco IOS, IOS XE, NX-OS and ASA, FortiOS, PAN-OS, Junos OS,
  RouterOS, VyOS, ArubaOS-CX. Another family keeps its vendor and product and goes through the
  applications table. Not a scan, no finding. A test: `detect snmp fetch`. New dependency `pysnmp`
  (extra `snmp` of the detect package, in the image).
- **The CMDB's NetworkDevice** gives its firmware too (brand, model, IOS version), the CPE only when
  the family is certain.
- **Level of proof embedded** (embarqué) in the watch: a firmware matched by its CPE, or by the
  vendor and the product as the records write them (`Cisco IOS XE Software`), in an affected range;
  possible while the record does not decide the version. A vendor that lists its affected versions
  one by one (Cisco) says which are not. In the alert sheet: the firmware, the fixed version, the
  source `firmware reported (snmp, <date>)`.
- **The vendors' CSAF advisories**: their product status (versions known affected, exact or `vers:`
  ranges; versions fixed) replaces the record's CNA block for the same product when the watch reads
  the advisory. `cisco-csaf` stays disabled in the catalogue: enable it for Cisco's versions.
- Schemas: a component may carry `cpe` (detection, assets, triage).
- Not verified on real devices: the sysDescr of each family and the vendors' version objects; the
  first reading prints `snmp: <n> targets, <m> devices, firmware known on <k>`.
- CI: the test PostgreSQL asks for a password on the loopback too (`POSTGRES_INITDB_ARGS`), as the
  work instance does.

**Upgrade**:

1. Move `ref` and `A2VM_REF` of the tenants to `v0.23.6`, and the watch to `via:v0.23.6`
   (`helm upgrade` of the tenant chart) for the level embedded.
2. A collector that reads SNMP: its image to `detect:v0.23.6`, then `systemctl daemon-reload`.
3. SNMP: the read-only user on the devices and its passwords in files (`docs/appliances.md` §2), the
   connector (§3), the source `snmp` in the tenant's `collectors.yaml`. The CMDB needs nothing.

## v0.23.5 — 2026-11-10

D20: Cyberwatch, read as a scanner.

- **Connector `cyberwatch` of the collector** (`docs/cyberwatch.md`, LLD detection §3.8), read only:
  the API keys of a Cyberwatch user (HTTP basic, API v3), GET requests only. The assets by pages,
  then each asset's details. One host per asset (name, FQDN, addresses, OS, Cyberwatch groups); its
  packages, else the current versions of its updates, as components of source `cyberwatch` (rpm and
  deb against the distributions' advisories, the others through the applications table); one finding
  per CVE still open on the asset (active, not fixed, not ignored in Cyberwatch), with the package,
  the version found and the target version of the update, and Cyberwatch's level. It is a scan: the
  asset counts as scanned. Options: `groups` (only some Cyberwatch groups), `include_ignored`, and
  the API paths (`assets_path`, `asset_path`), which changed between versions of Cyberwatch. A test:
  `detect cyberwatch fetch`. Not verified on a real master: the first reading prints
  `cyberwatch: <n> assets, <m> open CVEs, components on <k>`.

**Upgrade**:

1. Move `ref` and `A2VM_REF` of the tenants to `v0.23.5`; nothing changes in the services.
2. A collector that reads Cyberwatch: its image to `detect:v0.23.5`, then `systemctl daemon-reload`.
3. Cyberwatch: the user and its API keys (`docs/cyberwatch.md` §1), the connector (§2), the source
   `cyberwatch` in the tenant's `collectors.yaml`.

## v0.23.4 — 2026-11-09

A corporate network and the chat. Everything here is optional: a tenant upgraded without a new
variable runs as before.

- **Relay of the public sources** (topology R, `docs/hld/proposals/intel-placement.md`, the brief now
  kept in the repository): with `A2VM_RELAY_URL`, `A2VM_RELAY_HOSTS`, `A2VM_RELAY_TOKEN`, every
  request to a host listed (records, deltaLog, KEV, EPSS, CERT-FR, the watch's feeds and the CSAF
  documents found in them, package advisories) goes to `<relay>/<host>/<path>`, redirects included;
  a request with credentials (GTI) never does. `deploy/relay/`: Terraform and cloud-init for a
  small Scaleway instance with Caddy, one route per allowed host after the checks (addresses, token,
  credentials refused, GET and HEAD only), no CONNECT. `via check-sources` shows the route of each
  source; the watch and `via collect` log the relay.
- **Outgoing proxy**: `A2VM_HTTPS_PROXY`, `A2VM_NO_PROXY`, `A2VM_PROXY_CA` (the proxy's certificate,
  added to the system CAs, key `ca-bundle`) into the daily run, the watch's jobs and the shared
  service (chart `proxy.*`, `relay.*`).
- **`A2VM_INTEL_FALLBACK=false`**: a tenant whose shared service does not answer fails rather than
  reading the sources itself.
- **Another image registry** (Harbor): the job `images` pushes to `A2VM_PUSH_REGISTRY` /
  `A2VM_PUSH_IMAGE` with a robot account (`A2VM_PUSH_USER`, `A2VM_PUSH_PASSWORD`), the base image
  optionally through a mirror (`A2VM_PYTHON_IMAGE`); the tenants pull with `A2VM_IMAGE_REGISTRY`
  and `A2VM_REGISTRY_*` as before (`docs/kubernetes.md`).
- **Chat**: `list_new_cves` (the CVEs published or updated in a period, with when CVE.org published
  each, CVSS, KEV, EPSS, and the tenant's alert about it, if any; the shared service's
  `GET /v1/records/new`), `get_watch_status` (the watch's last passage and failing sources; the via
  service's `GET status`), `list_applications` (the applications table, paged). The tools'
  description tells the model to say when no tool covers a question, never to answer that nothing
  exists; `list_radar_events` says it lists only what the team validated.
  `tests/chat-questions.yaml`: 28 questions with the tool of each, checked by a test.
- **Portal**: a portal without data shows "No data" instead of SQL errors (the filters are
  `= ANY (ARRAY[…])`, valid when a variable has no option).
- **Publication**: on Kubernetes, a reporting database that refuses 3 runs in a row
  (`daily.publishFailures`) makes the daily job end failed, after the dispatch; before, a warning
  only.
- **Roadmap**: Cyberwatch in v0.23.5, appliances in v0.23.6, libraries in memory and SBOMs in v0.23.7.

**Upgrade**:

1. Move `ref` and `A2VM_REF` to `v0.23.4`: the tenant `via` first (the shared service answers the
   new tool), then the others. No image of the collector, no schema.
2. Portal on Kubernetes: `helm upgrade` of the chart `a2vm-portal` with its values to load the
   dashboards; cloud02: `verdict grafana` as for any dashboard change (`docs/reporting.md`).
3. A corporate network: deploy the relay (`deploy/relay/README.md`), set the relay's and the
   proxy's variables, check with `via check-sources`.
4. Harbor: the push variables in the code project, the pull variables in the tenants.

## v0.23.3 — 2026-11-09

D20, third step: SentinelOne's applications, and the tenant's applications table that maps the
applications of the EDRs to the products of the CVE records. Dispatch: a fix for iTop callers
whose name two persons carry, and the requested tickets left proposed.

- **Connector `sentinelone` of the collector** (`docs/sentinelone.md`, LLD detection §3.7), read only:
  an API token of a Viewer service user, GET requests only. `api: agents` (default, every console)
  reads the applications agent by agent; `api: installed-applications` by pages of the Application
  Risk inventory. One host per agent (name, FQDN when the domain is a DNS one, addresses, OS), every
  application as a component of source `sentinelone` with its publisher. Not a scan. A test:
  `detect sentinelone fetch`. Not verified on a real console yet: the first reading prints
  `sentinelone: <n> agents, applications listed on <m> (agents)`.
- **Wazuh**: the Windows and macOS packages keep their publisher (`vendor`), and are matched like
  SentinelOne's applications.
- **Applications table** (LLD intelligence §3.4): each inventory adds a row for each application the
  watch service does not know (`mozilla|mozilla firefox` for every version and language of
  Firefox); at each passage the tenant's LLM proposes the CPE of a few new rows (40,
  `A2VM_APPLICATIONS_PER_PASSAGE`); on the review page, **Applications**, a validator validates the
  proposal, types another CPE, marks the row as no product or resets it. The watch names a host
  **exposed** when a validated application is in an affected range of a new record (with the fixed
  version), **possible** when the record does not decide its version or the row is only proposed.
  The LLM never changes a decided row. GitLab mode: `applications.yaml` of the tenant project.
- **Watch service**: `GET applications`, `POST applications/proposals` (`via.v1.yaml`); with the
  tenant's database, the table `via.applications` (migration 2, at start). Library
  `a2vm.applications`, owned by pillar 3; `a2vm.packages` compares rpm and deb components only.
- **Dispatch**: the iTop `caller` is looked for in the tickets' organisation (`caller_organization`
  for another one), or by its e-mail when it holds an @: a name two persons carry is no longer
  refused ("caller_id: Several items found"). A ticket a person asked for and left `proposed`
  (asked in dry-run, or a failed sending) is sent again by the next live run, with the findings
  still open, or dropped when none is; the page shows the last error of a proposed ticket.

**Upgrade**:

1. Move `ref` and `A2VM_REF` of the client tenants to `v0.23.3` (the tenant `via` may follow:
   nothing of the shared service changes). The watch service creates its table at start.
2. A collector that reads SentinelOne or Wazuh: its image to `detect:v0.23.3`
   (`/etc/systemd/system/a2vm-collector@.service`), then `systemctl daemon-reload`.
3. SentinelOne: the service user and its token (`docs/sentinelone.md` §2), the connector (§3), the
   source `sentinelone` in the tenant's `collectors.yaml`.
4. After the next daily run, the review page lists the applications; with the tenant's LLM the
   proposals come within the next passages of the watch.
5. iTop refusing `caller_id: Several items found`: remove the duplicate Person, or give its e-mail
   as `caller`; the tickets left proposed go at the next daily run.

## v0.23.2 — 2026-11-07

The analysts' chat asks a period and the radar. SentinelOne moves to v0.23.3, the appliances to
v0.23.4, the libraries in memory and the SBOMs to v0.23.5.

- **A period in the chat** (`docs/chat.md` §8): `list_alerts` takes `since` and `until`, each a day
  or a date and time in the tenant's time zone (chart `chat.timezone`, Europe/Paris), sent to the
  services in UTC; a day alone covers all of it. Each alert says when it was drafted (`drafted_at`).
- **The radar in the chat**: `list_radar_events` gives the radar's events the watch team validated,
  from the shared intelligence service, between two moments, by level or CVE, newest first, counted
  by level by the tool server. GTI's items of the feed are left out (they name the technologies the
  tenants watch), the radar's candidates stay with the watch team.
- **Shared service**: `GET /v1/feed` also takes `until`, `kind`, `level`, `cve`, and `since` as a day
  or a date and time (`intel.v1.yaml`); a watch's mark works as before. Its network policy lets the
  tenants' tool servers in.
- **Watch service**: `GET alerts` takes `until` and a date and time for `since` (`via.v1.yaml`).

**Upgrade**:

1. Move `ref` and `A2VM_REF` of the tenant `via` to `v0.23.2` first (the feed's filters and the
   network policy of the shared service), then of the client tenants.
2. Nothing else: the tool server reads the key `intel-token` of the tenant's Secret, already there
   when `intel.url` is set (`A2VM_INTEL_URL`). A time zone other than Europe/Paris: `chat.timezone`.

## v0.23.1 — 2026-11-07

D20, second step: Wazuh's software inventory as a source of components, before the appliances
(the roadmap is reordered: SentinelOne v0.23.2, appliances v0.23.3, libraries in memory and SBOMs
v0.23.4).

- **Connector `wazuh` of the collector** (`docs/wazuh.md`, LLD detection §3.6), read only: the
  Wazuh indexer's inventory indices (`api: indexer`, recent versions) or the manager's API (`api:
  manager`, every 4.x version). One host per agent (name, address, OS), every package as a
  component of source `wazuh`, with the agent's distribution and the source package; a disconnected
  agent dated by its last keep-alive, one never connected left out. No finding: Wazuh's own
  vulnerability detection is not read. `detect wazuh fetch` for a test.
- **Pillar 3**: the components of Wazuh and of SSH side by side on the same host, each with its
  source and date; Wazuh is an inventory, not a scan of the host.
- **Watch**: a host known by Wazuh only is named like the others (`packages listed (wazuh, <date>)`).
  Windows and macOS software is kept, matched from v0.23.2.
- The packages listed over SSH and by Wazuh are built by the same code (`detect.collect.component`).

**Upgrade**:

1. Move `ref` and `A2VM_REF` of the tenants (`via` first, then the clients) to `v0.23.1` and push.
2. A read-only account in Wazuh (`docs/wazuh.md` §2), its password in a file of the collector.
3. The collector at `detect:v0.23.1`, a connector `wazuh` in its `collector.yaml` and its timer
   (`docs/wazuh.md` §3); the source `wazuh` in the tenant's `collectors.yaml`.

## v0.23.0 — 2026-11-07

First step of D20, the exposure from an inventory of components: the watch names the hosts whose
packages hold an affected version within minutes of a publication, without waiting for a scan.

- **Packages with their distribution** (pillar 2, `docs/scanning.md`): the SSH collection reads
  `/etc/os-release` and gives each package its distribution (`distro`, e.g. `rocky-9.4`) and its
  source package (`source_package`: `openssl` for `openssl-libs` or `libssl3`), in a `purl` with
  namespace and distro.
- **Components with their source and age** (pillar 3, LLD triage-prioritization §14.7): the asset
  keeps, for each source of components, its newest listing, each component with its `source` and the
  date it was seen (`seen`).
- **Package advisories in the records** (pillar 1): Red Hat's security data (RHEL and its rebuilds,
  Rocky Linux and AlmaLinux) and OSV (Debian, Ubuntu), read by CVE id only, become `packages` on each
  record (`vulnops.records/1`, a field added). Read only when asked: by the watch when the last
  inventory lists packages, by the shared intelligence service when a request carries `packages:
  true` (`intel.v1.yaml`). Settings `sources.packages_sources`, `redhat_url`, `osv_url`,
  `packages_cache_hours`.
- **Watch: hosts named with a level of proof** (`docs/alerts.md`): each new record is matched
  against the packages of the last daily inventory (`a2vm.packages`, rpm and dpkg version order).
  Each asset of the alert sheet carries a level in a new column (Proof / Preuve): `confirmed` (a scan
  saw the flaw), `exposed` (an affected version is installed, with the fix or "no fix yet" and the
  date of the listing, or a declared version is in the range), `possible` (the product is there, its
  version not decided: the distribution has not published or is investigating, a declared asset
  without version, a product named by the publication). A host exposed and open to the internet makes
  the alert urgent for a critical CVE. The level is evidence; the SSVC tables decide (D4).
- The neutral Word templates have the column Proof; a client's own template may add the field
  `{{ a.preuve }}` to its table of assets.
- HLD: D20 in progress, the roadmap split into v0.23.0 (this base), v0.23.1 (appliances and network
  devices, CSAF), v0.23.2 (libraries in memory, SBOMs), v0.23.3 (Wazuh, then SentinelOne) and later.

**Upgrade**:

1. The shared intelligence service first: move the tenant `via` to `v0.23.0` (`ref`, `A2VM_REF`) and
   push. It must reach `access.redhat.com` and `api.osv.dev` (HTTPS, through the proxy if any). An
   older service ignores the request for packages: the tenants' alerts then name only `possible`
   hosts.
2. Move `ref` and `A2VM_REF` of each client tenant to `v0.23.0` and push. No database schema change.
3. The collectors: run the install script again with `--image …/detect:v0.23.0`, or change the tag
   in the unit and pull the image (`docs/collectors.md` §2). Until then the packages have no
   distribution nor source package: they are compared on the host's OS and the binary name, so a
   library such as `openssl-libs` is not matched to `openssl`.
4. A client's own Word template may add the column `{{ a.preuve }}`.

## v0.22.2 — 2026-11-07

Consolidation: the respect of the SLA measured on when a fix happened, the radar's precision and
the LLM's proposals, three more questions for the chat, every package of each host.

- **SLA, when a fix happened** (D19, `docs/sla.md` §4): the reporting database (schema 6) places each
  fix between the last scan that still saw the flaw and the first that no longer did, and compares it
  with the deadline (the SLA due date, else BOD 26-04): `met (observed)`, `missed`, `met (declared,
  verified)` when the date the team declared in the ITSM lies in that interval on time, else `to
  verify`. Dispatch reads iTop's `resolution_date` when a ticket is resolved (`GET fixes`); the daily
  run's publication reads it with the dispatch read token. Dashboard `sla`: the fixes per status, and
  those missed or to verify.
- **Due date in iTop**: a target of `dispatch.yaml` may name a date field of the ticket (`due_field`,
  added by an iTop extension) that receives A2VM's due date on create and whenever it changes.
- **Radar** (`docs/radar.md`): each source weighs its own markers and the best counts; a publication
  that lists more than `bulk_cves` CVEs (10, a monthly vendor bulletin) never gathers by a shared CVE.
  With the tenant's LLM, the product of a publication that names none and the open event a new one
  may be the same news as are proposed and shown on the sheet to check; they decide nothing (D11).
- **Sharing the technologies** with the shared intelligence service is now optional per client,
  off by default (`alerts.share_technologies: true` in `client.yaml`); without it the client keeps
  the shared records and the radar's feed, and loses only GTI's search on its technologies.
- **Every package of each host** (first brick of D20): the SSH collection lists them (`rpm -qa`,
  else `dpkg-query`) after its method, the asset keeps them, the decision service answers `GET
  components`.
- **Analysts' chat**, each count computed by the services, never by the model:
  `list_closed_findings` takes `until` and several assets and answers counts by level and by asset;
  `list_tickets` gives the tickets sent to the ITSM between two days with their number (through the
  dispatch service); `find_component` the assets that carry a package, vulnerable or not.
- HLD: D20 (exposure from an inventory of components, planned v0.23.0, Wazuh then SentinelOne as the
  first EDR connectors); architecture, watch and tenants diagrams (`scripts/make_architecture_diagrams.py`).

**Upgrade**:

1. On each reporting database, `verdict db init` once before the first daily run of v0.22.2 (schema
   6, `docs/reporting.md`); a portal on Kubernetes does it at its upgrade. Import the dashboard `sla`
   again on a portal set up by hand.
2. Move `ref` and `A2VM_REF` to `v0.22.2` and push. The tools of the chat read the dispatch service
   when it runs (its read token is already in the Secret).
3. Watch: a client whose technologies should still feed GTI's search adds
   `alerts: {share_technologies: true}` to its `client.yaml`.
4. Optional: an iTop extension with a date field on `UserRequest`, named in `dispatch.yaml`
   (`due_field`).
5. The collectors list every package of their hosts once they run the v0.22.2 image: run the install
   script again with `--image …/detect:v0.22.2`, or change the tag in the unit and pull the image
   (`docs/collectors.md` §2). Until then the chat's `find_component` answers that the hosts are not
   listed.

## v0.22.1 — 2026-11-05

Fixes after the first deployment of v0.22.0. The consolidation planned as v0.22.1 becomes v0.22.2.

- **Chart**: the watch CronJob set `A2VM_CACHE_DIR` twice (shared environment, then its own). The
  next `helm upgrade` that changed its environment failed (`cannot patch "a2vm-<tenant>-watch" …
  $setElementOrder`), as v0.22.0 did. It is now set once; a test checks no container gives a name
  twice.
- **Pipeline**: `A2VM_K8S_SUSPEND` (`true`) keeps the daily CronJob suspended from one deployment to
  the next: the watch team's tenant has nothing to scan, and a `kubectl patch` was undone by the next
  deployment.
- **Shared intelligence service**: no log line per HTTP request it makes (one per CVE record).
- **Radar**: each passage logs the events it follows and how far the best are from the thresholds
  (`radar: N events in 14 days, alert at 4 (urgent 7); best: …`).
- **Operator's manual** (`docs/operations.md`) brought from v0.18.1 to this version: dispatch, the
  shared service and the radar, deploying again, the runner of the external scan, the failures met.

**Upgrade**: just before moving a tenant, delete its watch CronJob, which the deployment recreates
(the one of v0.22.0 still has the duplicate, and the upgrade would fail on it):
`kubectl -n a2vm-<tenant> delete cronjob a2vm-<tenant>-watch`. Then move `ref` and `A2VM_REF` to
`v0.22.1` and push. For the watch team's tenant, set the variable `A2VM_K8S_SUSPEND` to `true`
first. No database change.

## v0.22.0 — 2026-11-05

The shared intelligence service and the radar of the watch team (HLD D17).

- **Shared intelligence service** (`via intel-serve`, contract `intel.v1.yaml`, in the watch team's
  namespace `a2vm-via`): the records collected and enriched once for every tenant (CVE record, KEV,
  EPSS, GTI when enabled); `via collect` asks it for them when `A2VM_INTEL_URL` is set, and reads the
  sources itself when it cannot answer (said in the log). Each tenant's watch sends the technologies
  it watches (declared products and watchlist) at most twice a day; the service keeps them 48 hours
  without who sent them. One read token for the tenants (`A2VM_INTEL_TOKEN`, a group variable).
- **Radar of the watch team** (`alerts.mode: radar`, tenant `via`): the items of every source gathered
  into events (a shared CVE, titles sharing most of their words, a new CVE on the product of an event
  without one), zero-days before their CVE included; a deterministic magnitude (weight of the strongest
  source, markers in English and French: exploited in the wild, zero-day, without authentication,
  remote code execution, proof of concept; independent sources); alerts at 4 (info) and 7 (urgent),
  again when it rises and when its CVE appears. The sheet has the usual headings, the magnitude and
  every source. Research and news sources for the radar only (`radar_only`, disabled until checked).
- **To the clients**: a radar alert validated by the team is published to the shared service; every
  client's watch reads its feed (source `a2vm-intel`) and matches each event with its own assets,
  urgent when the radar said so. The radar never knows who has what.
- **GTI as discovery** (optional, off by default): the radar searches the vulnerabilities exploited,
  tagged zero-day or rated critical (source `gti-radar`); the shared service searches the
  technologies watched every 6 hours and puts the new ones in the feed with GTI's facts only.
- **Teams**: every alert drafted can also be posted to the analysts' Teams channel (an Adaptive
  Card with a button to the review page; the webhook's address in `A2VM_TEAMS_WEBHOOK`, never logged).
- Chart: `intel.url` (every tenant), `intel.serve.*` (the watch team), keys `intel-token`,
  `intel-radar-token`, `teams-webhook` of the tenant's secret; the deployment job makes them.
- Roadmap: the respect of the SLA measured on when a fix happened becomes a consolidation release (v0.22.2 since v0.22.1).

**Upgrade**: move `ref` and `A2VM_REF` to `v0.22.0` and push; nothing changes until the group has
`A2VM_INTEL_URL`. To use the radar and the shared service, follow `docs/radar.md`: the project `via`
(`A2VM_INTEL_SERVE=true`, its profile in radar mode, its review page), then the group variables
`A2VM_INTEL_TOKEN` and `A2VM_INTEL_URL`, then a deployment of every tenant. GTI and Teams are optional.

## v0.21.0 — 2026-11-04

Priorities and SLA per client, within the levels (HLD D19).

- BOD 26-04 stays the default SLA. A client may set its own priorities (free names: P0..Pn, Q0...) and
  their delays in its profile, section `sla` of `client.yaml`: rules of which the first that matches a
  decision applies, on its level, KEV, exposure, zone, EPSS, CVSS and the fields of its asset's CMDB
  item (criticality, class, status, organization, type); delays in calendar days (24/7) or business
  days (weekends, public holidays `FR` and the client's own days left out), in the client's time zone,
  for the client or per rule. ACT, ATTEND and TRACK do not change: a priority sorts a decision, it
  never changes it. The section is checked by the job `validate` (`docs/sla.md`).
- A delay starts on the day verdict puts the decision into its priority, kept in the tenant's
  database: a priority that goes up gets a new delay from the change, never beyond the due date
  already set; one that goes down keeps the due date announced. The daily run on Kubernetes reads that
  state before the triage (`verdict sla-state`, `GET sla-state` of `verdict.v1`, the publish token)
  and gives it to `verdict run --sla-state`; without it (GitLab pipeline mode, decision service not
  reached), the delays start at the first observation and the decisions and the report say so. The
  decisions open at the upgrade start from the day they got their level.
- Each decision records its priority, the rule applied, the start and its source, its SLA due date
  and the BOD 26-04 due date beside it (`sla` in `triage.json`; library `a2vm.sla`, owned by pillar
  3; deterministic, no LLM).
- Where it shows: `triage.csv` (`priority`, `sla_due`, `bod_due`); the daily report and the run page
  (section "Priorities and SLA", a column priority in the ACT and ATTEND tables); `verdict.v1`
  (`priority`, `priority_rank`, `sla_due` on each decision, filters `priority`, `sla_overdue`,
  `sla_due_before`, sorts `priority`, `sla_due`, `summary.sla`, `lifecycle.sla` and `priorities`); the
  chat (the same filters, the priorities in the summary, the CSV export, the explanation of the Word
  and PowerPoint documents); the reporting dataset and database, schema 5 (priority, SLA due date,
  `sla_status`, `deadline`, `within_sla`, SLA counts of each run); a new dashboard `sla` (priorities
  and SLA, its French and RSSI versions) and the priority of the findings fixed in `remediation`; the
  tickets (title `[A2VM ACT P1] …`, the SLA due date as the ticket's due date, the BOD one beside it,
  iTop impact and urgency per priority with `priorities` in the target of `dispatch.yaml`). The page
  of the requests accepts `priority` and `sla_overdue`.
- `tests/test_v0203.py`: the test of `db grant --password-file` is skipped without a disposable
  PostgreSQL, as the other database tests.

**Upgrade**: move `ref` and `A2VM_REF` to `v0.21.0` and push. Run `verdict db init` once on each
reporting database (schema 5, `docs/reporting.md`; a portal on Kubernetes does it at its upgrade),
then import the dashboard `sla` on a portal set up by hand. The tenant's database takes its
migration at the start of the decision service. A client with an SLA: add the section `sla` to its
`client.yaml` (`docs/sla.md`); without it, nothing changes.

## v0.20.3 — 2026-11-04

Several portals, and a portal on Kubernetes (D13 revised).

- A run publishes into several reporting databases: `A2VM_REPORTING_DSN` and each
  `A2VM_REPORTING_DSN_<NAME>` (with `A2VM_REPORTING_CA_<NAME>`), e.g. the operator's portal and one at
  the client; one that fails does not stop the others (exit 3, a warning). On Kubernetes
  `deploy-k8s` copies them into the tenant's Secret (`reporting-dsn-<name>`).
- Chart `deploy/charts/a2vm-portal`: the reporting database (CloudNativePG, writer `a2vm_writer`) and
  Grafana on Kubernetes; the data source and the dashboards of the version provisioned (the RSSI
  versions with the page's address when `dashboards.dispatchUrl` is set), no import by hand; a job
  runs `verdict db init` and gives Grafana its reading role after each install and upgrade; sign-in
  with the identity provider (`viewers`, `admins`); NetworkPolicies; an optional LoadBalancer for
  publishers outside the cluster.
- `verdict db grant --password-file`: a password kept elsewhere (a Secret) instead of a new one.
- HLD D13 revised: portals wherever their readers want them, several possible.

**Upgrade**: move `ref` and `A2VM_REF` to `v0.20.3` and push; nothing else changes for a tenant.
For a portal on Kubernetes or another portal: `docs/reporting.md`.

## v0.20.2 — 2026-11-03

The page of the requests for remediation answers on large selections.

- A selection of thousands of decisions (an asset with many findings, every ACT) was read 200 at a
  time from the decision service and outlasted oauth2-proxy's 30 seconds: the page answered 502.
  `GET decisions` accepts pages of up to 2000 (`verdict.v1`, added only; 200 elsewhere), which the
  dispatch service reads, and the proxy of the page waits up to 120 seconds
  (`dispatch.page.proxy.timeoutSeconds`). A client gone before the answer is one line in the log.

**Upgrade**: move `ref` and `A2VM_REF` to `v0.20.2` and push; no database change, no dashboard to
import again.

## v0.20.1 — 2026-11-03

Fixes of v0.20.0.

- The dispatch service reaches the tenant's database: its pods were missing from the
  NetworkPolicy of the CloudNativePG cluster, so the service stopped at start (connection timeout)
  and the page of the requests answered 502.
- `A2VM_CHAT_MAX_CHARS`: the longest answer of a tool of the chat, per tenant (default 8000
  characters, about 2,000 tokens; 4000 for a model with a 16k context, which a long conversation
  fills with the tools' answers).
- `docs/dispatch.md`: the address of the page asked at the import of the RSSI dashboards, and how to
  change it afterwards (the constant `dispatch_url`).

**Upgrade**: move `ref` and `A2VM_REF` to `v0.20.1` and push; no database change.

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
