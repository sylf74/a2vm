# Deployment modes: where a client's data is processed

One code base, one pipeline template. Each client project chooses where its jobs run with two
CI/CD variables, set in the client project (they default to `llm-lan`, one runner for everything):

| Variable | Jobs | What they handle |
| --- | --- | --- |
| `VULNOPS_RUNNER_DATA` | validate, collect, cve-list, detect, assets, triage, watch, send-alerts | Client profile, targets, scans, findings, contacts; calls to the LLM |
| `VULNOPS_RUNNER_PUBLIC` | intel, watch-discover | Public data only: CVE records, KEV, EPSS, GTI, watch sources; a list of CVE ids |

The LLM endpoint is chosen per client too (`VULNOPS_LLM_BASE_URL`, `VULNOPS_LLM_MODEL`, `LLM_API_KEY`
in the client project override the group values).

## The three modes

| Mode | `VULNOPS_RUNNER_DATA` | LLM | For | Needs |
| --- | --- | --- | --- | --- |
| On-prem MSSP (default) | runner in the MSSP data centre | GPU server in the data centre | Default; sensitive clients | Network path to the client's hosts or scanners; dedicated runner and LLM for PDIS clients |
| At the client | runner installed at the client | GPU server at the client | Clients whose data must not leave | The runner reaches the MSSP GitLab (VPN). Reports and artifacts are stored in the MSSP GitLab: if that is not acceptable either, the client needs its own GitLab |
| Cloud | runner in the company cloud | GPU VM in the company cloud | Non-sensitive clients that accept the cloud by contract | Private link from the cloud to the client's hosts or scanners |

In every mode, `VULNOPS_RUNNER_PUBLIC` can point to a shared runner in the company cloud, joined to
the GitLab network by a private link (VPN or ExpressRoute) and allowed out to the source domains.
Runners only make outbound connections: a cloud runner works with an on-prem GitLab as long as it
can reach it.

## Choosing a mode for a client

1. Classification: PDIS or highly sensitive clients go on-prem (MSSP or client), never to the cloud.
2. Contract and TLP: material marked TLP:AMBER or TLP:RED, or a contract excluding cloud processing,
   rules out the cloud mode.
3. Network: collection runs where it can reach the client's hosts or scanners.
4. Cost: a GPU VM in the cloud running all the time for a few clients costs more than a share of an
   on-prem GPU server.

## Guardrails for public jobs

Public jobs never receive client data:

- No checkout of the client project (`GIT_STRATEGY: none`). They read only `settings.yaml` and
  `watch-sources.yaml` from it, with a partial clone that fetches those two files.
- Their input from the collection is `cve-list/cve-ids.txt`, a separate artifact with CVE ids and
  nothing else: no host name, package or version.
- They run in the `public-data` environment, the data jobs in `client-data`. Scope the client
  secrets (`VULNOPS_SSH_KEY`, `LLM_API_KEY`, `VULNOPS_SMTP_PASSWORD`) to `client-data` in the client
  project so that public jobs never receive them. On GitLab Free, environment scopes exist for
  project variables only: a secret set on the group reaches every job, so set those per project.
- Reserve the public runner to the `vulnops` group, with its own tag, and allow it out only to
  GitLab and the source domains.

Open point per client: the list of CVE ids found on its assets carries no asset name, but it tells
which vulnerabilities the client has. If that list must not leave the data zone, keep
`VULNOPS_RUNNER_PUBLIC` equal to `VULNOPS_RUNNER_DATA` for that client.

## Registering a runner for a mode

Same procedure as `docs/deployment.md` §2, with the tag of the mode, for example `cloud-public`
(public jobs in the cloud), `cloud-data` or `client-<id>` (data jobs). Then, in the client project,
Settings > CI/CD > Variables: `VULNOPS_RUNNER_DATA`, `VULNOPS_RUNNER_PUBLIC`, and the LLM variables
when the LLM differs.
