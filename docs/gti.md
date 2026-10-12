# Google Threat Intelligence (optional)

vulnops can ask Google Threat Intelligence (GTI, the VirusTotal API v3) what it knows about each
CVE: exploitation state, exploit availability, risk rating. It needs a GTI Enterprise or
Enterprise Plus licence; without one, leave it disabled (the default) and nothing changes.

## What is sent, what comes back

One request per CVE: `GET https://www.virustotal.com/api/v3/collections/vulnerability--cve-yyyy-nnnn`
with the `x-apikey` header. **Only the CVE id leaves the network**: nothing about the client
(assets, versions, exposure) is sent.

The answer is reduced to a small view stored in `records.json` (`gti` field of each record):

| Field | Used for |
| --- | --- |
| `exploitation_state` (no known, reported, suspected, confirmed, wide) | SSVC *Exploitation* |
| `exploit_availability` (none, known, publicly available, trivial) | SSVC *Exploitation* |
| `first_exploitation`, `exploit_release_date` | analyst note, alert sheet |
| `risk_rating` (or `predicted_risk_rating`, flagged) | analysts |
| `exploitation_consequence`, `exploitation_vectors`, `available_mitigation` | analysts |
| `executive_summary` | analysts only, see below |

## Effect on decisions

SSVC *Exploitation* takes the highest value given by any source; a source never lowers another:

| GTI | Exploitation |
| --- | --- |
| confirmed or wide | `active` |
| publicly available or trivial exploit | `poc` |
| no known, no exploit | `none` |
| reported or suspected, without a public exploit | no opinion; the row is flagged for review |

Ties are attributed to KEV first, then GTI, then CISA ADP. In watch mode, exploitation confirmed by
GTI makes an alert urgent, as a KEV entry does (GTI often sees exploitation before KEV lists it).

## Licensed content

GTI's prose (executive summary, analysis) belongs to Google. It is kept in `records.json` for the
analysts, never sent to the LLM and never copied into client deliverables. Client alert sheets only
state facts (exploitation confirmed by GTI, date of first exploitation, public exploit). Check that
your GTI contract allows these facts to be passed on to clients (MSSP use).

## Set-up

1. GTI web interface: **API key** (user menu). A service account's key is better than a person's.
2. Group `vulnops` (or one client project) > **Settings > CI/CD > Variables**:

| Key | Value | Options |
| --- | --- | --- |
| `GTI_API_KEY` | the key | Masked, protected |
| `VULNOPS_GTI_ENABLED` | `true` | Visible |
| `VULNOPS_GTI_MAX_CALLS` | `2000` (optional) | Visible |

3. The runner must reach `www.virustotal.com` (HTTPS; `HTTPS_PROXY` / `SSL_CERT_FILE` are honoured).

Each `intel` and `watch` job prints one line on start-up (`GTI: enabled, ... api key set`) and one
at the end (`GTI: n/m CVE known to GTI (k lookups, rest from cache)`). A refused key (HTTP 401 or
403) stops the lookups for the run after the first refusal; the pipeline goes on without GTI.

## Quota

Answers are cached 24 h (`gti_cache_hours`) in the job cache. `gti_max_calls` caps the network
lookups per run; CVEs not in KEV and with the highest CVSS and EPSS are looked up first, since they
are the ones GTI can move. HTTP 429 answers are retried (three times, honouring `Retry-After`).

Test the key by hand from the runner:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H "x-apikey: $GTI_API_KEY" \
  https://www.virustotal.com/api/v3/collections/vulnerability--cve-2024-3400
```

`200`: key and licence fine. `401`: wrong key. `403`: key without vulnerability intelligence access.
