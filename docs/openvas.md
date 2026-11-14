# OpenVAS network scans (Greenbone Community Edition)

NGVM (pillar 2, detect) drives a Greenbone scanner (gvmd + OpenVAS) over GMP: it creates or reuses a target and a
task per client, starts the scan, waits for it and imports the XML report. A report exported from
the Greenbone web interface can also be imported by hand.

What it adds to the SSH collection (Trivy, dnf): no account on the targets, and a view of what is
reachable on the network (services, versions seen from outside, appliances where no agent runs).
What it does not replace: package-level detail, which only a local collection gives.

## 1. Where to run the scanner

A network scanner sees what its network position lets it see:

| Placement | Sees | Use |
| --- | --- | --- |
| A VM inside the client network (or the lab) | Internal hosts and services | Internal vulnerability scan |
| A host on the internet (VPS) | Only what the client exposes to the internet | External exposure, a check of the `exposure: open` declarations |

Scan only addresses the client owns and has agreed to have scanned. A cloud or VPS provider may
restrict outbound scanning in its terms: scanning your own public addresses is usually allowed,
check before scheduling.

The scanner never needs to reach GitLab: the pipeline's runner connects to the scanner (GMP), not
the other way round.

## 2. Install Greenbone Community Edition (containers)

Follow the official guide, "Greenbone Community Containers" (greenbone.github.io/docs): Docker,
the compose file it provides, `docker compose up -d`, then wait for the first feed synchronisation
(it can take hours; scans before it is complete find little). Size the VM generously: the scanner
and its database need several cores and several GB of RAM.

Create a dedicated GMP account for NGVM (named `vulnops`, unchanged since v0.11.0 to keep existing set-ups), with the User role (not Admin):

```bash
docker compose exec -u gvmd gvmd gvmd --create-user=vulnops --role=User --password='<password>'
```

## 3. Expose GMP to the runner, with mutual TLS

gvmd listens on a Unix socket inside the containers. Publish it over TLS with client certificates,
so that only the runner holding the client certificate can open a GMP session (the GMP password is
the second factor). A small CA, one server certificate, one client certificate:

```bash
mkdir certs && cd certs
openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/CN=vulnops GMP CA" -keyout ca.key -out ca.pem
openssl req -newkey rsa:3072 -nodes -subj "/CN=<scanner host name>" -keyout server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -out server.crt \
  -extfile <(printf "subjectAltName=DNS:<scanner host name>")
cat server.crt server.key > server.pem
openssl req -newkey rsa:3072 -nodes -subj "/CN=vulnops-runner" -keyout client.key -out client.csr
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -out client.crt
```

`compose.override.yaml`, next to the official compose file:

```yaml
services:
  gmp-tls:
    image: alpine/socat
    command: >-
      OPENSSL-LISTEN:9390,reuseaddr,fork,cert=/certs/server.pem,cafile=/certs/ca.pem,verify=1
      UNIX-CONNECT:/run/gvmd/gvmd.sock
    volumes:
      - gvmd_socket_vol:/run/gvmd
      - ./certs:/certs:ro
    ports:
      - "9390:9390"
    depends_on:
      - gvmd
    restart: on-failure
```

Open TCP 9390 on the scanner host to the runner's address only.

## 4. Client project

`targets.yaml`, an `openvas` section (with or without SSH targets):

```yaml
client: lab
openvas:
  gmp: tls://scanner.lab.example:9390   # or unix:///run/gvmd/gvmd.sock on the scanner host itself
  hosts: [192.0.2.0/24]                 # addresses, ranges or names the scanner must reach
  exclude: [192.0.2.1]
  # scan_config: daba56c8-73ec-11df-a475-002264764cea   Full and fast (default, safe checks on)
  # port_list:   33d0cd82-57c6-11e1-8ed1-406186ea4fc5   All IANA assigned TCP (default)
  # min_qod: 70                         quality of detection threshold (Greenbone's default view)
  # timeout_minutes: 240                how long the collect job waits for the scan
  # reuse_hours: 6                      a scan finished less than this ago is collected, not redone
  # gmp_timeout_seconds: 300            wait for one answer of gvmd (v0.18.2)
  # gmp_reconnects: 3                   new connections when gvmd does not answer in time (v0.18.2)
  # zone: lan                           the zone of client.yaml the scanner observes from (v0.24.0)
```

`zone` (v0.24.0) names the zone, among the `zones` of `client.yaml`, where the scanner stands. Each
open port the scan finds is then a port reached from that zone: the asset graph of pillar 3 turns it
into a flow between zones (`lan -> dmz 5432/tcp`), proof that the host is reachable (exposure
`controlled` when the external scan does not reach it), and an exposure gap `undeclared-flow` when
no flow of the profile allows it. Without `zone`, the ports still prove the host reachable, but give
no flow. A scanner allowed everywhere by the firewalls observes more than an ordinary host of its
zone can reach: place it where the flows it sees mean something, or read its flows as an upper bound.

A full scan of a few hosts on every TCP port takes hours. The GitLab job timeout (1 h by default)
must be longer than `timeout_minutes`: set it in the client project, **Settings > CI/CD > General
pipelines > Timeout** (e.g. `5h`), and check the runner's own maximum job timeout. If the job is
killed anyway, gvmd goes on scanning: a later run waits for the running scan, or collects the
finished one when it is younger than `reuse_hours`.

gvmd sometimes takes minutes to answer one command: while it loads a feed update, or writes a
large report. When it does not answer within `gmp_timeout_seconds`, the collection opens a new
connection, signs in again and makes the same call (reading the task, downloading the report),
`gmp_reconnects` times at most for the whole scan; the scan goes on in gvmd meanwhile. A start of
the scan that got no answer is never sent twice: the task is read again, and a running scan is
followed. A command gvmd refused (wrong id, permissions) is not retried. Each new connection is a
line of the job log or of the collector's journal: `openvas: gvmd did not answer get_task
(TimeoutError: timed out): new connection 1/3`. Raise `gmp_timeout_seconds` (e.g. `900`) on a slow
scanner host rather than `gmp_reconnects`.

List each address once: a host name and the address it resolves to are two targets for the
scanner, and the same machine is then scanned twice.

CI/CD variables of the client project:

| Key | Type | Value |
| --- | --- | --- |
| `NGVM_GVM_USER` | Variable | `vulnops` |
| `NGVM_GVM_PASSWORD` | Variable, masked, protected | the GMP password |
| `NGVM_GVM_CA` | File | `ca.pem` |
| `NGVM_GVM_CERT` | File, protected | `client.crt` |
| `NGVM_GVM_KEY` | File, protected | `client.key` |

Check the file with `detect plan targets.yaml` (the validate job does it). The daily
`collect` job then runs the scan; it needs no `NGVM_SSH_KEY` when the file has no SSH target.

## 5. Scanner host as runner (external scans)

Since v0.18.2, `deploy/scanner` builds such a host on Scaleway with Terraform and cloud-init
(Greenbone, the runner, the GMP account, a daily feed update): its README replaces steps 1 and
2 below. The steps say what it does, for a host installed by hand.

For a scanner outside the network that holds the client data (a cloud instance scanning the
public exposure), the scanner host can run the `collect` job itself: GMP then goes through the
local socket, port 9390 stays closed, and only the collection runs there; the other jobs (intel,
triage with the LLM) stay on the internal runner and get the detection through the job artifacts.

1. On the scanner host, install GitLab Runner (Docker executor) and register it as a **project
   runner** of this client project only, with its own tag (e.g. `scan-cloud`). If GitLab is
   reached through a reverse proxy that asks for a client certificate, give the runner its
   certificate and the public URL:

   ```toml
   [[runners]]
     url = "https://gitlab.example.org"          # public name of the reverse proxy
     clone_url = "https://gitlab.example.org"
     tls-cert-file = "/etc/gitlab-runner/certs/scanner.crt"
     tls-key-file = "/etc/gitlab-runner/certs/scanner.key"
     environment = ["NGVM_SERVER_URL=https://gitlab.example.org"]
     [runners.docker]
       volumes = ["/cache", "greenbone-community-edition_gvmd_socket_vol:/run/gvmd"]
   ```

   `NGVM_SERVER_URL` makes the job fetch the vulnops code by the public URL; the client
   certificate is handed to git through `CI_SERVER_TLS_CERT_FILE` and `CI_SERVER_TLS_KEY_FILE`.

2. In the client project, run the collection there and talk to gvmd over the socket:

   ```yaml
   # .gitlab-ci.yml
   variables:
     NGVM_COLLECT_TAG: scan-cloud
   ```

   ```yaml
   # targets.yaml
   openvas:
     gmp: unix:///run/gvmd/gvmd.sock
     hosts: [203.0.113.10, www.example.org]
   ```

   Only `NGVM_GVM_USER` and `NGVM_GVM_PASSWORD` are needed (no certificates over a socket).

The scanner host then holds a runner token and, while a job runs, a job token: register it on
this project only, and keep client projects with internal data on internal runners.

## 6. Joining the external scan to the internal run (v0.11.2, token v0.11.3)

The external scan usually lives in its own collection-only project (`<client>-external`), so that
the internal project, which holds the client's internal data, never runs on the cloud scanner. The
internal pipeline then brings the external detection in, and one decision is taken per asset and
CVE (LLD triage, section 5.3).

1. **External project** (`vulnops/clients/<client>-external`): its daily `collect` job keeps
   `work/detect/` as artifacts; the internal project reads the latest one. Give the internal
   project a way in, one of:
   - **a project access token** (recommended, required on GitLab CE, v0.11.3): in the external
     project, Settings > Access tokens, role Reporter, scope `read_api`, with an expiry date. Store
     it in the internal project as the CI/CD variable `NGVM_GITLAB_TOKEN` (masked, protected).
     The latest successful `collect` job is then found among the project's jobs, whatever other
     pipelines run there;
   - **the job token**: Settings > CI/CD > Job token permissions, add the internal project (or
     the group `vulnops/clients`). GitLab then serves the `collect` job of the latest successful
     pipeline of `main` only: any other pipeline on `main` (a push, another schedule) hides it,
     and some GitLab editions do not let a job token read another project's artifacts.
2. **Internal project**: CI/CD variable (or `.gitlab-ci.yml` variable)
   `NGVM_EXTERNAL_PROJECT: vulnops/clients/<client>-external`.
3. **Internal profile** (`client.yaml`): name the external client and map the public endpoints to
   the internal assets that answer behind them:

   ```yaml
   external:
     client: <client>-external        # the client id of the external targets.yaml
     max_age_days: 8                  # an older external scan is left out, with a warning
   published:
     - endpoint: "www.example.org:443"   # public name or address, optional port
       asset: rproxy01                   # declared asset id, or host name / FQDN of a scanned host
       behind: [gitlab01, app01]         # assets reached through it
       zone: dmz
   ```

4. **Schedules**: run the external collection before the internal daily pipeline.

In the internal `collect` job, `detect external` prints what it took (hosts, findings, scan
date) or why it left the external scan out (none yet, too old, another client, no access): the
job then ends in warning and the run goes on without it. In the report, the exposure of the
assets the external scan reached reads "ouverte (Internet), scan externe".

## How results are read

- One asset per scanned host (IP, host name, OS when the scanner found them); it merges with the
  same host seen by Trivy or dnf (same FQDN, host name or address).
- Every open port found (v0.24.0), from the results of any severity and the report's port list,
  as the host's services, seen from the scanner's `zone`; a host with open ports and no finding is
  an asset too.
- One finding per host and CVE; the port and the NVT are kept on each observation, with the
  installed and fixed versions when the NVT reports them, and its CVSS vector (v4 or v3, else the
  v2 vector of older NVTs).
- A generic test that lists 5 CVEs or more without reporting an installed version (for instance
  "HTTP Debugging Methods (TRACE/TRACK) Enabled", which cites the CVEs of every product that once
  had the flaw) gives findings in status `under_investigation`, flagged for review: the product is
  not confirmed. The same CVE reported by a specific test is not flagged.
- CVE ids rejected by the CVE program but still cited by an NVT are listed as ignored in the
  report, not as errors.
- Left out, and counted: results below the QoD threshold (guesses from banners), log-level
  results, results without a CVE (configuration findings such as weak TLS ciphers).
- The report is parsed with defusedxml (no entity expansion, no external entities): it carries
  strings chosen by the scanned hosts.

## Manual import

Export the report from the web interface (Reports, download, format XML), then:

```bash
detect import --client lab --source openvas report.xml --out work/detect
```

Add `--zone lan` when the scanner stands in a zone of `client.yaml` (v0.24.0).
