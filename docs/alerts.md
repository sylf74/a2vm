# Watch mode: alerts before the morning press review

Every 10 minutes, each client project checks what is new and drafts an alert when it concerns the
client. An analyst validates it with one click; only then is it mailed to the client.

```
every 10 min   the sources of config/watch-sources.yaml, in three categories:
                 institutional  CERT-FR (alerts, advisories), CISA (KEV, advisories), CERT-EU, ...
                 vendor         Microsoft, Cisco, Fortinet, Palo Alto, HPE (RSS), Siemens (CSAF),
                                and vendors without a feed (Dell, Lenovo, Supermicro, AMI, VMware,
                                Ivanti...) through their CVE records as CNAs
                 research       Zero Day Initiative
      |
      v        does it concern this client?
               - a CVE matches a declared asset (vendor / product / CPE / versions), or
               - the publication (or the CVE record) names a declared product or a watchlist entry
               - the client's last daily inventory found the CVE on one of its hosts
               - a CVE already alerted in the last 14 days is skipped, unless it becomes KEV
      v
               alert sheet (French, team layout): why now and from which source, table of the
               assets concerned, CVE, product, type, CVSS, main impact, exploitation status, fixes,
               description, delay, links
      v
               mail to the analysts (A2VM_ANALYST_TO), naming the recipients, with a link
      v
               analyst runs the manual job "send-alerts"  ->  mail to the client's contacts
```

Sources (`config/watch-sources.yaml`, or `watch-sources.yaml` in a client project to replace it):

| kind | reads | notes |
| --- | --- | --- |
| `certfr` | CERT-FR RSS, then the JSON view of each publication | affected systems, risks, vendor advisories |
| `kev` | CISA KEV | always urgent |
| `cvelist` | new CVE records (cvelistV5 delta log) | matched against assets and watchlist |
| `rss` | RSS 2.0, Atom, RDF | CVE ids and product names taken from title and summary |
| `csaf` | CSAF provider metadata, then `changes.csv` or ROLIE | products, fixes and severity in the sheet |
| `cna` | nothing by itself | labels the CVE records of a vendor without a feed |

A source is read for the first time only to record its current state (no flood of old news).
Sources marked `enabled: false` have URLs still to be checked from the runner:

```bash
via check-sources --sources config/watch-sources.yaml
```

Levels:

| Level | When | Sent for |
| --- | --- | --- |
| `urgent` | KEV, CERT-FR alert, exploitation or proof of concept reported by CISA, or a critical CVE on an Internet-exposed asset | every client |
| `info` | CERT-FR advisory on a product of the client, without the above | clients with `alerts.level: all` |

## Assets concerned and the daily inventory (v0.11.2)

The watch reads the client's last daily inventory: `work/assets/<client>/assets.json` and
`findings.json`, which the daily `triage` job leaves in the runner cache (key `inventory`, since
v0.11.3). Without that copy (first run, cache cleared, another runner), the watch asks GitLab for
the artifacts of the last `triage` job; GitLab only serves the latest successful pipeline of the
branch, which is nearly always a watch, unless `A2VM_GITLAB_TOKEN` is set. With several runners,
give them a shared cache (S3, MinIO) so that the watch finds the copy. An alert then also covers a CVE the daily
pipeline found on a host, even when no declared asset or watchlist entry names the product, and a
critical CVE on a host the external scan reaches is urgent.

The sheet lists the assets concerned in a table:

| Column | From |
| --- | --- |
| Actif | Asset name (detected), description (declared), product (watchlist) |
| Zone | Declared asset or profile rule |
| Exposition | Exposure and its source (external scan, declared, rule, assumed) |
| Version installée / corrigée | Package and versions observed by the scanners |
| Responsable | Owner, when declared or set by a rule |
| Source | Detected (package scan, dnf updates, network scan, external scan), declared, watchlist, product cited by the publication |

Under the table: "Inventaire du JJ/MM/AAAA", the date of the inventory used. The job log says
which inventory was read; older than 8 days it is flagged `WARN`, and without one (no daily run
yet, artifacts expired after 30 days) the watch goes on with the declared assets only.
`via watch --inventory none` disables it, `--inventory <dir>` reads a local copy.

Limit: a detected host is named only for a CVE already in the last daily findings. A CVE
published since the last daily run is matched against declared assets and the watchlist only,
until the full package list of each host is collected.

## Validation and sending (v0.11.3)

The analysts' mail gives the alert's number in its pipeline ("Alerte n° 2 sur 3") and its id. In
the pipeline the mail links to, ▶ on `send-alerts` sends every alert of that pipeline. To send only
some of them, open the job's form (the arrow next to ▶) and set the variable `A2VM_SEND_ONLY` to
their numbers or ids, e.g. `1 3`. An unknown number or id sends nothing: the job fails and says
which; correct it and run the job again.

What happened is kept in three places:

| File | Where | Content |
| --- | --- | --- |
| `alerts/index.json`, `*.md`, `*.html` | `watch` job artifacts (14 days) | The alerts of that run |
| `alerts/sent.json` | `send-alerts` job artifacts (90 days) | The mails sent to the client by that job: alert, recipients, result |
| `alerts-log.jsonl` | Runner cache `.watch/`, copied into the artifacts of every `watch` and `send-alerts` job | Journal of every alert: drafted, mailed to the analysts (or failed), sent to the client (or failed); the last 5,000 events |

To find an alert or a mail, open the artifacts of the latest `watch` job and read
`alerts/alerts-log.jsonl` (one JSON line per event, with the pipeline link).

**Editing a sheet before sending (v0.11.4):** put the corrected text in `edits/<alert id>.md`
(and, for the Word file, `edits/<alert id>.docx`) of the client project, on the default branch,
then ▶ on `send-alerts`. The links in the analysts' mail lead to the text and the Word file to
start from. An edited sheet that cites a CVE the alert does not is refused. See
`docs/alert-word.md`.

**Word and PDF (v0.11.4):** with `alerts.attach` in `client.yaml`, every alert also comes as a
Word file, filled from the client's template (`templates/alert.docx`) or the neutral one. The
analysts receive the Word file; the client receives it (`docx`), or a PDF made from it at sending
time (`pdf`), or both (`docs/alert-word.md`).

**Checking the mail settings:** run a pipeline (Build > Pipelines > New pipeline, or ▶ on a
schedule), then ▶ on the manual job `test-mail`. It sends one message to `A2VM_ANALYST_TO`, or to
the addresses set as `A2VM_TEST_TO` in its form, and prints the sender and the transport.

**Source failures:** a source that fails once (a vendor site down for a few minutes) is a `WARN`
line in the log; it becomes an error, and the job a warning (orange), after 3 failed runs in a row
(`A2VM_SOURCE_FAILURES`). One successful run resets the count.

**CISA advisories:** read as CSAF from CISA's repository on GitHub (`cisagov/CSAF`, ICS and IT
advisories, products and fixes included), since the RSS feed of cisa.gov answers 403 to the
runners (v0.11.3).

Facts in the sheet (identifiers, scores, versions, dates, links, assets) are written by code from
the sources. The local LLM only writes "impact principal" and "description" from those facts and
the source texts, behind the same guard as the triage rationales; on rejection the sheet uses the
CERT-FR summary or the vendor's description.

## Set-up

1. Group `vulnops` > Settings > CI/CD > Variables (shared by all clients):

   | Key | Example | Options |
   | --- | --- | --- |
   | `A2VM_SMTP_HOST` | `smtp.example.com` | Visible |
   | `A2VM_SMTP_PORT` | `587` | Visible |
   | `A2VM_SMTP_TLS` | `starttls` (or `ssl`, `none`) | Visible |
   | `A2VM_SMTP_USER` | `alerts@example.com` | Visible |
   | `A2VM_SMTP_PASSWORD` | | Masked and hidden, protected |
   | `A2VM_MAIL_FROM` | `Veille vulnérabilités <alerts@example.com>` | Visible |
   | `A2VM_ANALYST_TO` | `analyst1@example.com, analyst2@example.com` | Visible |

   Without `A2VM_SMTP_HOST`, nothing is sent: messages are written to `alerts/outbox/*.eml`
   (job artifacts), which is a convenient dry run.

   **Per client:** a variable set on a client project overrides the group's one. A client whose
   alerts must leave from its own Microsoft 365 tenant (or another relay) gets its own mail
   variables in its project; the others use the group's.

   **Microsoft 365 (Exchange Online):** SMTP with a password (Basic auth) is being switched off by
   Microsoft; use Microsoft Graph instead (`A2VM_MAIL_TRANSPORT=graph`):

   | Key | Value |
   | --- | --- |
   | `A2VM_MAIL_TRANSPORT` | `graph` |
   | `A2VM_GRAPH_TENANT_ID` | directory (tenant) id |
   | `A2VM_GRAPH_CLIENT_ID` | application (client) id |
   | `A2VM_GRAPH_CLIENT_SECRET` | client secret — masked and hidden, protected |
   | `A2VM_GRAPH_SENDER` | mailbox that sends, e.g. `veille@example.com` |

   In Entra ID: App registrations > New registration; Certificates & secrets > New client secret;
   API permissions > Microsoft Graph > Application permissions > `Mail.Send`, then grant admin
   consent. Restrict the application to the sending mailbox only (Exchange Online RBAC for
   Applications, or an application access policy): without it, `Mail.Send` allows sending as any
   mailbox of the tenant.

2. In `client.yaml` of the client project:

   ```yaml
   alerts:
     recipients: [rssi@client.example]
     level: urgent                  # or: all (CERT-FR advisories on the client's products too)
     watchlist: ["Fortinet FortiOS", "Microsoft Exchange Server"]   # products not declared as assets
   ```

   Contacts with their role go in `contacts.yaml` of the client project (optional; checked by the
   `validate` job; `via contacts client.yaml` lists who receives what):

   ```yaml
   schema_version: 1
   contacts:
     - {name: Jeanne Martin, role: RSSI, email: rssi@client.example}
     - {name: CERT, role: CERT, email: cert@client.example}
     - {name: Paul Durand, role: DSI, email: dsi@client.example, receive: [urgent]}
     - {role: chef du SOC, email: soc@client.example, active: false, notes: "absent until 3 Nov"}
   ```

   `receive` filters by alert level (default: both), `active: false` keeps a contact on file without
   sending. The analysts' mail names who will receive the alert (name and role) before validation.

3. Client project > Build > Pipeline schedules > New schedule: `*/10 * * * *`, branch `main`,
   variable `A2VM_JOB` = `watch`. Keep the daily triage schedule as it is.

The first run records what already exists and alerts on nothing. The state lives in the GitLab
cache (`.watch/state.json`); if the cache is cleared, the next run records a new baseline.

## Limits (to address with the PostgreSQL storage)

- An edited sheet is plain Markdown: tables and lists as the watch writes them; the mail
  renders headings, paragraphs, lists and tables only.
- The journal is a file in the runner cache: clearing the cache empties it (the artifacts of past
  jobs keep their copies until they expire).
- Without on-call duty, alerts found at night wait for the first analyst in the morning: the gain
  is that they are drafted, matched and one click away when the analyst arrives.
- Scanned hosts are used through the last daily findings only (see above): a brand-new CVE is not
  matched against the packages installed on the hosts yet.
- The CERT-FR JSON view is read defensively: a missing field degrades the sheet (fewer details),
  it does not stop the watch.
