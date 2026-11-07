# The radar of the watch team and the shared intelligence service (v0.22.0)

A client's watch only alerts on what concerns that client: its declared assets, its watchlist, its
last daily inventory. The radar is the watch of the team itself: it follows the major
vulnerabilities whoever they concern, zero-days before their CVE included, and the team decides
which clients to alert. It sits beside the shared intelligence service, which collects the records
once for every tenant and carries the radar's validated events to the clients' watches (HLD D17;
design: LLD vulnerability-intelligence §3.10 to §3.12).

```
 sources (CERT-FR, KEV, CVE, vendors, research, news; GTI search, optional)
      |
      v
 radar (tenant via, alerts.mode: radar)          every 10 minutes
   items gathered into events, magnitude  ->  alert to validate (review page, mail, Teams)
      |                                              |
      |                                     validated by the team
      v                                              v
 shared intelligence service (a2vm-via)  <-  the event published
   records for every tenant, feed
      |
      v
 each client's watch (source a2vm-intel)  ->  matched with ITS assets  ->  its own alert to validate
```

![The watch: shared service, radar and the clients' watches](hld/watch.svg)

## 1. What makes an event major

The radar gathers the items of every source into events: the same CVE; else titles sharing most of
their words; else a new CVE on the product an event without CVE names. A publication that lists
more than `bulk_cves` CVEs (10; a monthly vendor bulletin) never gathers by a shared CVE: its CVEs are
many distinct flaws. Its magnitude is computed, never asked to the LLM: each source weighs its own
weight and the markers of its own texts, the best source counts, then the other sources add their
bonus (v0.22.2; before, the markers of every source were added together, which made a bulletin of
twenty flaws look like one exploited pre-authentication RCE):

| Part | Points |
| --- | --- |
| The strongest source: KEV, exploitation confirmed by GTI, or a source whose publications are all urgent (CERT-FR alerts) | 3 (any other source: 1) |
| A CVSS of 9 or more | +1 |
| Exploited in the wild (or KEV, or GTI says so) | +3 |
| Zero-day | +2 |
| Without authentication; remote code execution; proof of concept | +1 each |
| Each other independent source | +2 (6 at most) |

The texts are read in English and French. An event is alerted at 4 (`info`) and at 7 (`urgent`),
again when it moves up a level, and once more when it gets its first CVE ids. A zero-day blog post
on a pre-authentication RCE exploited in the wild is urgent on its own (1 + 3 + 2 + 1 + 1 = 8); a
flaw that three research sites report is `info` (1 + 4).

Each passage logs the events followed and the best scores against the thresholds, so that a passage
without alerts can be read: `radar: 12 events in 14 days, alert at 4 (urgent 7); best: 3 '…', …`.

## 2. The watch team's tenant `via`

A tenant project like the others (`vulnops/clients/via`, namespace `a2vm-via`), on Kubernetes, with
the review page and the sign-in of the analysts (`docs/sign-in.md`). Its `client.yaml`:

```yaml
schema_version: 2
client:
  id: via
  name: Watch team
  updated: 2026-11-05
  language: en
alerts:
  mode: radar
  radar: {info: 4, urgent: 7, window_hours: 72, keep_days: 14, bulk_cves: 10}
```

The daily run has nothing to scan: `A2VM_K8S_SUSPEND` `true` keeps its CronJob suspended (a
`kubectl patch` would be undone by the next deployment). Its
`contacts.yaml` names the team (the validated radar alerts are mailed to them). Its CI/CD
variables, beside those of every tenant on Kubernetes:

| Variable | Value |
| --- | --- |
| `A2VM_RUN_MODE` | `kubernetes` |
| `A2VM_K8S_SUSPEND` | `true` |
| `A2VM_INTEL_SERVE` | `true`: the shared intelligence service runs in this namespace |
| `A2VM_VERDICT_SERVICE` | `false`: no decision service, nothing to decide |
| `A2VM_ALERTS_HOST`, `A2VM_OIDC_*` | the review page of the team (`docs/sign-in.md`) |
| `A2VM_TEAMS_WEBHOOK` | optional, masked: the team's Teams webhook (§5) |
| `A2VM_GTI_ENABLED`, `GTI_API_KEY` | optional: the GTI search (§4) |

The radar reads the catalogue of the version (`config/watch-sources.yaml`) and the sources marked
`radar_only`: the GTI search and research and news sites. These sites start disabled: check them
from the runner, then enable them in a `watch-sources.yaml` of the project (a copy of the catalogue).

```bash
via check-sources --sources config/watch-sources.yaml
```

## 3. The shared intelligence service and the tenants

The group `vulnops/clients` holds one read token, the same for every tenant: the service does not
tell the tenants apart. Create it once, as a masked and protected variable of the group:

| Variable (group) | Value |
| --- | --- |
| `A2VM_INTEL_TOKEN` | 64 random hexadecimal characters (`openssl rand -hex 32`) |
| `A2VM_INTEL_URL` | `http://a2vm-via-intel.a2vm-via.svc:8080` |

The deployment of the project `via` writes the digest of that token, and of its own radar token,
into the Secret `a2vm-intel`. A tenant that must be revoked alone gets its own token: its digest
(`printf '%s' "$TOKEN" | sha256sum`) as a line `read <sha256>` of the File variable
`A2VM_INTEL_DIGESTS` of the project `via`.

Then, at their next deployment, every tenant:

- asks the shared service for its records (`via collect`), and reads the sources itself when it
  cannot answer (said in the log);
- sends the technologies it watches (declared products and watchlist) at most twice a day, when
  its profile says `alerts.share_technologies: true` (v0.22.2, off by default): the service keeps
  them 48 hours, without who sent them, and GTI searches them; without it the client keeps the
  shared records and the radar's feed and loses only that search;
- reads the shared feed (source `a2vm-intel`): a validated radar event that names one of its
  products, or a CVE found on its assets, becomes its own alert to validate, urgent when the radar
  said so.

On a GitLab tenant (`A2VM_RUN_MODE: gitlab`), the same variables work if the runner reaches the
service (an ingress of your choice).

## 4. GTI (optional, off by default)

With `A2VM_GTI_ENABLED=true` and `GTI_API_KEY` in the project `via` (an Enterprise licence):

- the radar searches every 10 minutes the vulnerabilities GTI changed since the day before with an
  exploitation confirmed or wide, tagged zero-day or rated critical (source `gti-radar`; the filter
  can be replaced by `query` in the catalogue). Only the filter leaves the network;
- the shared service searches every 6 hours the vulnerabilities GTI changed in the last two days on
  each technology the tenants watch; a new one enters the feed with GTI's facts only (exploitation
  state, exploit availability, risk rating) and a link. Only the technology's name leaves the network.

GTI's prose never reaches a client. Check the filter syntax against the GTI documentation of
`GET /collections` and that your contract allows these facts to be passed on (MSSP use).

## 5. Teams

Every alert the watch drafts, the radar's and every client's, can also be posted to the analysts'
Teams channel: create a webhook (Teams, the channel, *Workflows*, "Send webhook alerts to a
channel"), and give its address as the masked variable `A2VM_TEAMS_WEBHOOK` of the project (the
deployment puts it in the Secret `a2vm-tenant`, key `teams-webhook`). The card says the level, the
title, the CVE ids, the tenant and, for the radar, the magnitude, with a button to the review page.

## 6. Upgrading to v0.22.0

1. Every tenant: `ref` and `A2VM_REF` to `v0.22.0`. Nothing else changes until the group has
   `A2VM_INTEL_URL`: the jobs read the sources themselves, as before.
2. The project `via` (§2) and the group variables (§3); deploy `via` first, then the others.
3. Optional: GTI (§4), Teams (§5).
