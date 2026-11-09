# How the watch reaches the Internet: a relay of the sources, or the radar in the cloud

Status: planned. Topology R (the relay of the sources, §4.6) and the outgoing proxy (§4.3) in
v0.23.4; the cloud cluster (§4.1, §4.2, §4.4) later, when an operator needs it (HLD §11).

Written after v0.23.2. Read with HLD `docs/hld/00-product-strategy.md` (D17, §6, §11),
`docs/radar.md`, `docs/kubernetes.md` and the chart `deploy/charts/a2vm-tenant`.

## 1. Need

The radar (tenant `via`, `alerts.mode: radar`) and the shared intelligence service (`via
intel-serve`, D17) read about fifteen public sites every 10 minutes (CISA, CERT-FR, GitHub
cvelistV5, vendors' feeds and CSAF, optionally GTI). In a corporate network behind a proxy, that
means a flow request per site, TLS inspection, sites filtered by category, and automated traffic the
SOC will question.

The way out must be a configuration choice, never imposed:

- an operator who runs everything in one cluster (the homelab today) keeps doing so, unchanged;
- an operator who runs every tenant in a cloud cluster can;
- an operator who keeps the client tenants on premises (a corporate cluster, or GitLab mode) can put
  only the radar and the shared service in a small cloud cluster. The client tenants then reach the
  shared service over HTTPS: one outgoing flow to one domain instead of a dozen sites;
- an operator who keeps everything on premises (radar, shared service, LLM, data) can send the
  requests to the public sources through a relay on a small cloud VM: one outgoing flow to one
  domain, nothing else moves (§4.6, **the recommended first step**).

## 2. What exists (v0.23.2)

| Item | State |
| --- | --- |
| Cluster of a tenant | Already chosen per tenant: `A2VM_K8S_CONTEXT` (GitLab agent context). Two tenants can live in two clusters today |
| Address of the shared service | `intel.url` (variable `A2VM_INTEL_URL` of the group `vulnops/clients`), an in-cluster address (`http://a2vm-via-intel.a2vm-via.svc:8080`); token: key `intel-token` of the tenant's Secret |
| Shared service | `intel.serve.enabled` in the watch team's release; a ClusterIP Service, **no Ingress**; its NetworkPolicy lets in only the pods `daily`, `watch`, `send`, `tools` of the namespaces in `intel.serve.allowNamespaces` (empty: every namespace of the cluster) |
| Tool server of the chat | NetworkPolicy egress to the intel pods of the cluster only (`namespaceSelector: {}`, port 8080): **an external intel URL is blocked** |
| Daily run and watch CronJobs | No NetworkPolicy: free egress |
| GitLab mode | Works with `A2VM_INTEL_URL` if the runner reaches the service (`docs/radar.md` §3), but no ingress is provided to reach it |
| Outgoing proxy | No setting in the chart. The HTTP clients are `httpx` with the default `trust_env=True`: `HTTPS_PROXY` and `NO_PROXY` in the environment would be honoured (to check in every client: sources, LLM, intel, mail, Graph, Teams, GTI) |
| Cloud VMs | Terraform and cloud-init patterns already in the repo: `deploy/portal` (reporting, Scaleway, Caddy and Let's Encrypt), `deploy/scanner` (runner `scan-cloud`). No cloud cluster |
| Fallback | A tenant whose shared service does not answer reads the sources itself (`collect` → `collect_direct`, noted in the log) |

## 3. Topologies to support

| | Radar and shared service | Client tenants | Link | Typical case |
| --- | --- | --- | --- | --- |
| A | Same cluster | Same cluster | In-cluster Service (today) | Homelab |
| B | Cloud cluster (k3s on a VM, or managed) | On-premises cluster(s) | HTTPS ingress of the shared service, read token per tenant | Corporate network behind a proxy |
| C | Cloud cluster | Same cloud cluster | In-cluster Service | Everything in the cloud |
| D | Any cluster | GitLab mode (runner) | HTTPS ingress | Client without Kubernetes |
| R | On premises, any of A to D | On premises | In-cluster; the public sources through a relay of the sources on a cloud VM | Corporate network behind a proxy, everything kept inside |

A, C: nothing changes. R needs §4.6 and the proxy of §4.3 when the relay itself is reached through
the corporate proxy. B, D need §4.1, §4.2, and §4.4 for a cloud cluster.

## 4. Proposed design

### 4.1 Expose the shared service (watch team's release)

- `intel.serve.ingress`: `enabled`, `host` (variable `A2VM_INTEL_HOST`), `className`, `tls`
  (cert-manager issuer or an existing secret), `annotations`, optional source allowlist
  (`allowCidrs`: the corporate egress addresses; the chosen ingress controller's annotation).
- NetworkPolicy of the intel pod: also allow the ingress controller's namespace (value
  `intel.serve.ingress.controllerNamespace`).
- Unchanged: per-tenant read token (digests), `radar` token for the team's sender, only CVE ids leave
  a tenant, technologies only with `alerts.share_technologies: true` (off by default).
- To consider: a rate limit per token on `/v1/records` (a tenant's daily run asks thousands of CVEs).

### 4.2 Reach an external shared service (client tenants)

- `intel.url` may be `https://…`. The chart then knows the service is outside the cluster
  (`intel.external`, derived from the URL or explicit):
  - the tool server's egress allows TCP 443 to `intel.egressCidrs` (default `0.0.0.0/0`, to narrow
    down) instead of the in-cluster intel pods;
  - the jobs keep their free egress (no change), unless a later version restricts it.
- `intel.ca`: a private CA for the intel certificate (variable `A2VM_INTEL_CA`, File), mounted and
  given to the client (`SSL_CERT_FILE` or an explicit `verify`).
- GitLab mode: the same `A2VM_INTEL_URL` and `A2VM_INTEL_TOKEN`; document it.

### 4.3 Outgoing proxy (any tenant, any topology)

- Group or project variables `A2VM_HTTPS_PROXY`, `A2VM_NO_PROXY`, `A2VM_PROXY_CA` (File) → chart
  values `proxy.https`, `proxy.noProxy`, `proxy.ca` → environment `HTTPS_PROXY`, `HTTP_PROXY`,
  `NO_PROXY` and a CA bundle in every pod that goes out (daily, watch, send, radar, intel, tools,
  dispatch). `NO_PROXY` keeps the cluster's services (`.svc`, `.cluster.local`), the LLM endpoints
  and the ITSM when they are internal.
- Check each HTTP client honours them (httpx `trust_env`), including the SMTP sender (no proxy: SMTP
  must be reachable directly or through a relay) and Microsoft Graph.
- The same for the collectors (`docker run -e HTTPS_PROXY …` in the unit) if they need the
  Internet (they normally do not).

### 4.4 A cloud cluster for the watch team (optional, provider-specific)

- `deploy/cloud-k8s/` on the pattern of `deploy/portal`: Terraform (Scaleway first) for one
  instance, its public address and its security group (22 and 6443 from `admin_ips`, 80 and 443
  open or restricted); cloud-init (provider-agnostic) installing k3s (Traefik, local-path storage),
  cert-manager with Let's Encrypt, and the GitLab agent (`helm install` with the agent token read on
  the instance, never through Terraform).
- Sizing: radar, shared service, review page, oauth2-proxy, optionally CloudNativePG: 2 vCPU,
  4 GiB, 40 GB as a start; to measure.
- Then the tenant `via` points `A2VM_K8S_CONTEXT` to the new agent, `A2VM_INTEL_HOST` set, and the
  group variable `A2VM_INTEL_URL` becomes `https://<host>`.

### 4.5 What the cloud radar needs from elsewhere

| Need | Options |
| --- | --- |
| LLM (radar proposals, translation of the team's alerts) | A vLLM endpoint reachable from the cloud (TLS, key), or `alerts.radar.llm_calls: 0` and English only |
| Mail of the team's alerts | SMTP relay reachable from the cloud, or Microsoft Graph |
| Review page sign-in | The identity provider (OIDC) reachable from the analysts and from the cluster; redirect URI on the cloud host |
| Images | The registry reachable from the cloud nodes (pull secret already made by `deploy-k8s`) |
| GitLab | The cluster's agent connects out to GitLab (KAS): GitLab must be reachable from the cloud |

### 4.6 A relay of the sources (topology R, recommended first)

A small cloud VM runs an HTTPS reverse proxy (Caddy, on the pattern of `deploy/portal`) with **one
route per allowed upstream host and nothing else**:

```
https://relay.example.org/www.cisa.gov/...                 -> https://www.cisa.gov/...
https://relay.example.org/raw.githubusercontent.com/...    -> https://raw.githubusercontent.com/...
https://relay.example.org/www.cert.ssi.gouv.fr/...         -> https://www.cert.ssi.gouv.fr/...
https://relay.example.org/access.redhat.com/...            -> https://access.redhat.com/...
https://relay.example.org/api.osv.dev/...                  -> https://api.osv.dev/...
```

- **Not a forward proxy, not a tunnel**: no CONNECT, no open destination; the VM reaches only the
  hosts listed. For the corporate proxy it is ordinary HTTPS to one domain, which it may inspect;
  no proxy chaining. Declared to the SOC with the list of the hosts.
- **Rewriting in one place, in the code**: the sources' URLs are settings (`cve_record_url`,
  `delta_log_url`, `kev_url`, `epss_url`, `certfr_url`, `redhat_url`, `osv_url`, `gti_url`) and
  catalogue entries (`watch-sources.yaml`), but some URLs are found in the data and followed (CSAF:
  `provider-metadata.json` → ROLIE feeds and documents; links of feeds). Changing each URL by hand
  would miss those. Hence a setting `sources.relay`: `url` (`https://relay.example.org`), `hosts`
  (the hosts sent through it), `token_file`. One hook in the HTTP clients of the sources and the
  watch's feeds rewrites `https://<host>/<path>` into `<url>/<host>/<path>` for a host listed, adds
  the relay's token, and leaves every other URL alone. Unset: nothing changes (topologies A to D).
- **What crosses the relay**: public feeds, CVE ids. The relay terminates TLS, so it sees the
  headers: **no authenticated API through it** (GTI key, SentinelOne token, Microsoft Graph, Teams
  webhook, the LLM): those stay direct or through the corporate proxy (§4.3). The relay rejects a
  request carrying an `Authorization` or `x-apikey` header for an upstream other than its own token.
- **Access to the relay**: its own token (header checked by Caddy) and the corporate egress
  addresses in an allowlist; otherwise it is an open relay to those sites.
- **Cache** (optional): Caddy's cache or a short `Cache-Control` override for the large static files
  (KEV, EPSS), to spare the upstreams; the A2VM caches stay the reference.
- **`deploy/relay/`**: Terraform (Scaleway) for the instance, its address, its security group (443
  from the allowed addresses, 22 from `admin_ips`); cloud-init (provider-agnostic) with Caddy, the
  host list from a variable, the token generated on the instance and read over SSH (never through
  Terraform). Sized like the smallest instance.
- **The collectors** need nothing: they reach the hosts, the detection service and the registry,
  not the Internet.
- **Check**: `via check-sources` reports, per source, whether it went through the relay.

## 5. Security

- Topology B puts no client data in the cloud: the shared service holds public records, the radar's
  events, and (opt-in) technologies without who sent them (D17). To state in the HLD.
- TLS everywhere outside a cluster; tokens per tenant (already); source allowlist on the ingress;
  logs of the service's calls without the tokens.
- A client tenant that cannot reach the service falls back to the sources (already): a cut flow
  degrades, it does not stop the watch. A tenant that must never go to the Internet needs the
  opposite: an option `intel.fallback: false` so that it fails rather than reading the sources.

## 6. Work items

0. Topology R first (v0.23.4): `sources.relay` (settings, environment `A2VM_RELAY_URL`, `A2VM_RELAY_HOSTS`,
   `A2VM_RELAY_TOKEN` into the tenant's Secret), the rewriting hook in every client that fetches a
   public source (via sources, feeds and CSAF, packages advisories, EPSS, KEV, CERT-FR, cvelist),
   `check-sources` showing the route, `deploy/relay/` and its README, `docs/radar.md` and
   `docs/deployment.md`.
1. Chart: `intel.serve.ingress.*`, NetworkPolicy of the intel pod (ingress controller),
   `intel.external`, `intel.egressCidrs`, `intel.ca`, `proxy.*` on every pod that goes out.
2. Pipeline template: variables `A2VM_INTEL_HOST`, `A2VM_INTEL_CA`, `A2VM_HTTPS_PROXY`,
   `A2VM_NO_PROXY`, `A2VM_PROXY_CA` passed to helm; the CA files into the Secret or a ConfigMap.
3. Code: `intel.fallback` (sources setting); one place that builds the httpx clients with the CA
   and the proxy; check SMTP, Graph, Teams, GTI, LLM.
4. `deploy/cloud-k8s/` (Terraform Scaleway + cloud-init k3s, cert-manager, GitLab agent), README.
5. Docs: HLD D17 (placement as a choice, topologies A to D), §6 (contract unchanged: `intel.v1.yaml`
   over HTTPS), §11 roadmap; `docs/radar.md` (topologies, ingress, proxy), `docs/kubernetes.md`
   (variables), LLD intelligence §3.10 (exposure, fallback), CHANGELOG, upgrade steps.
6. Tests: chart rendering of each topology (CI helm job), NetworkPolicy of the tool server with an
   external URL, proxy variables in the pods, `intel.fallback: false`, client with a private CA.

## 7. Acceptance

- Topology R: with `sources.relay` set, every request to a listed host goes to the relay (CSAF
  documents found in a provider's metadata included), no request to a listed host goes direct, no
  authenticated API goes through the relay; unset, the requests are those of v0.23.2.

- Topology A: a tenant upgraded with no new variable renders the same objects as v0.23.2 (no
  ingress, same NetworkPolicies, no proxy variables).
- Topology B: a client tenant with `A2VM_INTEL_URL=https://intel.example.org` gets its records and
  the radar's feed, and its chat's `list_radar_events` answers.
- Behind a proxy: with `A2VM_HTTPS_PROXY` only, a tenant reads the shared service and the LLM as
  configured, nothing else goes direct.
- `intel.fallback: false`: an unreachable service fails the run with a clear message, no source is
  read.

## 8. Open questions

0. Relay: Caddy (as `deploy/portal`) or nginx? Its name and certificate (Let's Encrypt on a public
   name)? Does GTI, if enabled at work, go direct through the corporate proxy (recommended)?
1. Cloud cluster: k3s on a Scaleway instance (cheap, managed by us), or Kapsule (managed control
   plane, more expensive)? The brief assumes k3s on an instance.
2. Ingress controller and certificates: Traefik of k3s with cert-manager and Let's Encrypt (public
   name), or a private CA?
3. Is the team's review page exposed on the same cloud host, behind the same OIDC?
4. Which LLM for the cloud radar: the homelab's vLLM exposed, a hosted endpoint, or none?
5. Version (decided): the relay (topology R) and the outgoing proxy (§4.3) in v0.23.4, after
   SentinelOne (v0.23.3); Cyberwatch comes in v0.23.5, appliances in v0.23.6, libraries in memory and SBOMs in v0.23.7; the
   cloud cluster (§4.1, §4.2, §4.4) later.

## 9. Recommendation

1. **v0.23.4: the relay of the sources (§4.6) and the outgoing proxy settings (§4.3).** It solves
   the corporate case with the least change: the radar, the shared service, the LLM and the data stay
   inside; one declared flow to one domain; nothing changes for the homelab when unset.
2. **The cloud cluster (§4.1, §4.2, §4.4) as a later option**, for an operator who wants the radar
   or every tenant in the cloud; not needed for the corporate case once the relay exists.
3. **Never a forward proxy or tunnel on the cloud VM**: proxy chaining through the corporate proxy
   is fragile, and the SOC would see it as a way around its proxy.
