# SentinelOne's application inventory (v0.23.3)

SentinelOne's agents list the applications installed on each machine. NGVM reads that inventory as
a source of components (`sentinelone`): one host per agent, every application with its version and
its publisher. Application names are free text, so the watch matches them against the CVE records
through the tenant's **applications table**: the tenant's LLM proposes the CPE of each application,
a validator decides on the review page (§4). NGVM never changes anything in SentinelOne, and does
not read SentinelOne's own vulnerability data. Design: LLD detection §3.7, LLD intelligence §3.4,
LLD triage §14.7.

## 1. Which API

| `api` | Requests | For |
| --- | --- | --- |
| `agents` (default) | `GET /web/api/v2.1/agents`, then `GET /web/api/v2.1/agents/applications` agent by agent | Every console |
| `installed-applications` | `GET /web/api/v2.1/agents`, then `GET /web/api/v2.1/installed-applications` by pages | Consoles with Application Risk: fewer requests on a large fleet |

## 2. Read-only account

In the management console, Settings > Users > Service Users: a service user `ngvm-inventory`, role
**Viewer**, at the scope of the tenant's account (or of its sites), with an expiry date your policy
allows. Its API token is shown once: paste it on the collector into a file readable by the agent
only, without typing it on a command line:

```bash
sudo sh -c 'umask 077; cat > /etc/ngvm/collector/sentinelone-token'
```

```bash
sudo chown 10001:10001 /etc/ngvm/collector/sentinelone-token
```

The first command waits for the token: paste it, press Enter, then Ctrl-D. Check from the collector
(one agent expected):

```bash
sudo sh -c 'curl -sS -H "Authorization: ApiToken $(cat /etc/ngvm/collector/sentinelone-token)" "https://console.lab.example/web/api/v2.1/agents?limit=1"' | head -c 400
```

Before the token expires, make a new one and replace the file: nothing else changes.

## 3. Connector on the collector

In `/etc/ngvm/collector/collector.yaml` (`docs/collectors.md` §2):

```yaml
connectors:
  - name: lan-s1
    type: sentinelone
    url: https://console.lab.example
    api: agents                                   # or installed-applications
    token_file: /etc/ngvm/collector/sentinelone-token
    site_ids: ["1234567890"]                      # optional: the tenant's sites only
    # account_ids: ["9876543210"]
    # ca_file: /etc/ngvm/collector/ca.pem         # a private CA (console behind a proxy)
    # page_size: 500                              # items per request, 1 to 1000
    # timeout_seconds: 120
```

Its timer runs before the daily run (`sudo systemctl enable --now ngvm-collector@lan-s1.timer`). In
the tenant project, `collectors.yaml` declares the source with the collector's others:
`sources: [trivy, dnf-updateinfo, openvas, cmdb, wazuh, sentinelone]`. The journal shows
`sentinelone: <n> agents, applications listed on <m> (agents)`, then `ok   sentinelone [<url>]: <n>
agents`. A test without the collector:
`detect sentinelone fetch --config s1.yaml --tenant lab --out work/detect`.

## 4. The applications table

- Each daily inventory brings the applications of SentinelOne and of the Windows and macOS agents
  of Wazuh to the watch service, which adds a row `new` for each application it does not know. A
  row is an application whatever its version, architecture or language: `Mozilla Firefox (x64 fr)`
  and `Mozilla Firefox (x64 en-US)` by `Mozilla` are one row.
- At each passage of the watch the tenant's LLM proposes the CPE of a few rows (40, the most
  widespread first; `NGVM_APPLICATIONS_PER_PASSAGE`), or none for a driver, a runtime or an update.
- On the review page (`https://<alerts host>/applications`), a validator validates the proposal,
  types another CPE (`cpe:2.3:a:<vendor>:<product>`, as in the NVD dictionary), marks the row as
  no product, or resets it. The decision is kept with who made it; the LLM never changes it.
- The watch names a host **exposed** when a validated row's application is in an affected range of
  a new CVE record (with the fixed version when the record gives it), **possible** when the record
  does not decide its version, or when the row is only proposed ("mapping to validate").
- In the GitLab mode there is no watch service: `applications.yaml` in the tenant project is the
  table, each line validated by its merge request. The watch's log says how many applications have
  no CPE yet.

```yaml
applications:
  - {vendor: Mozilla, name: Mozilla Firefox, cpe: "cpe:2.3:a:mozilla:firefox"}
  - {vendor: Igor Pavlov, name: 7-Zip, cpe: "cpe:2.3:a:7-zip:7-zip"}
  - {vendor: Intel Corporation, name: Intel Graphics Driver}    # no cpe: not a product, never matched
```

The table says which product an application is; the versions of the record and the SSVC tables
decide (D4, D11).

## 5. When the connector fails

| Journal | Cause | Remedy |
| --- | --- | --- |
| `SentinelOne not reached` | Address, DNS, firewall, certificate not trusted | `curl` of §2 from the collector; `ca_file` |
| `SentinelOne refused the token (401)` | Token expired, revoked, or not the one of the file | A new token in the file |
| `SentinelOne refused the token (403)` | The user's role or scope does not read the agents or their applications | Role Viewer at the tenant's scope; `site_ids` within it |
| `SentinelOne answered 429` | Rate limit after three waits | A larger `page_size`, `api: installed-applications`, or a timer further from other API clients |
| `answered something else than JSON` | `url` is not the console (a sign-in page) | The console's address, without `/web/api` |
| `token_file … is empty` | The file is missing or empty | Its path in `collector.yaml`, §2 |

Not verified yet on a real console: the field names of the agents and applications lists, taken
from the API's documentation. The first reading tells: a count of agents and of agents with
applications in the journal, the hosts and their applications in the chat (`find_component`).
