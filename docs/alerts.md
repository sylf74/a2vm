# Watch mode: alerts before the morning press review

Every 10 minutes, each client project checks what is new and drafts an alert when it concerns the
client. An analyst validates it with one click; only then is it mailed to the client.

```
every 10 min   CERT-FR alerts and advisories (RSS + JSON of each publication)
               CISA KEV additions
               new CVE records: critical (CVSS >= 9) or exploited according to CISA ADP
      |
      v        does it concern this client?
               - a CVE matches a declared asset (vendor / product / CPE / versions), or
               - the CERT-FR publication names a declared product or a watchlist entry
      v
               alert sheet (French, team layout): why now, assets concerned, CVE, product,
               type, CVSS, main impact, exploitation status, description, delay, links
      v
               mail to the analysts (VULNOPS_ANALYST_TO), with a link to the pipeline
      v
               analyst runs the manual job "send-alerts"  ->  mail to the client
```

Levels:

| Level | When | Sent for |
| --- | --- | --- |
| `urgent` | KEV, CERT-FR alert, exploitation or proof of concept reported by CISA, or a critical CVE on an Internet-exposed asset | every client |
| `info` | CERT-FR advisory on a product of the client, without the above | clients with `alerts.level: all` |

Facts in the sheet (identifiers, scores, versions, dates, links, assets) are written by code from
the sources. The local LLM only writes "impact principal" and "description" from those facts and
the source texts, behind the same guard as the triage rationales; on rejection the sheet uses the
CERT-FR summary or the vendor's description.

## Set-up

1. Group `vulnops` > Settings > CI/CD > Variables (shared by all clients):

   | Key | Example | Options |
   | --- | --- | --- |
   | `VULNOPS_SMTP_HOST` | `smtp.example.com` | Visible |
   | `VULNOPS_SMTP_PORT` | `587` | Visible |
   | `VULNOPS_SMTP_TLS` | `starttls` (or `ssl`, `none`) | Visible |
   | `VULNOPS_SMTP_USER` | `alerts@example.com` | Visible |
   | `VULNOPS_SMTP_PASSWORD` | | Masked and hidden, protected |
   | `VULNOPS_MAIL_FROM` | `Veille vulnérabilités <alerts@example.com>` | Visible |
   | `VULNOPS_ANALYST_TO` | `analyst1@example.com, analyst2@example.com` | Visible |

   Without `VULNOPS_SMTP_HOST`, nothing is sent: messages are written to `alerts/outbox/*.eml`
   (job artifacts), which is a convenient dry run.

   **Per client:** a variable set on a client project overrides the group's one. A client whose
   alerts must leave from its own Microsoft 365 tenant (or another relay) gets its own mail
   variables in its project; the others use the group's.

   **Microsoft 365 (Exchange Online):** SMTP with a password (Basic auth) is being switched off by
   Microsoft; use Microsoft Graph instead (`VULNOPS_MAIL_TRANSPORT=graph`):

   | Key | Value |
   | --- | --- |
   | `VULNOPS_MAIL_TRANSPORT` | `graph` |
   | `VULNOPS_GRAPH_TENANT_ID` | directory (tenant) id |
   | `VULNOPS_GRAPH_CLIENT_ID` | application (client) id |
   | `VULNOPS_GRAPH_CLIENT_SECRET` | client secret — masked and hidden, protected |
   | `VULNOPS_GRAPH_SENDER` | mailbox that sends, e.g. `veille@example.com` |

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

3. Client project > Build > Pipeline schedules > New schedule: `*/10 * * * *`, branch `main`,
   variable `VULNOPS_JOB` = `watch`. Keep the daily triage schedule as it is.

The first run records what already exists and alerts on nothing. The state lives in the GitLab
cache (`.watch/state.json`); if the cache is cleared, the next run records a new baseline.

## Limits (to address with the PostgreSQL storage)

- The alert cannot be edited before sending: correct `client.yaml` or wait for the next one.
- Without on-call duty, alerts found at night wait for the first analyst in the morning: the gain
  is that they are drafted, matched and one click away when the analyst arrives.
- Scanned hosts (Trivy, dnf) are not used for matching yet, only declared assets and the
  watchlist: OS package vulnerabilities rarely make CERT-FR alerts, and they are in the daily triage.
- The CERT-FR JSON view is read defensively: a missing field degrades the sheet (fewer details),
  it does not stop the watch.
