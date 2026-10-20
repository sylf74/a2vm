# OpenVAS network scans (Greenbone Community Edition)

A2VM (pillar 2, detect) drives a Greenbone scanner (gvmd + OpenVAS) over GMP: it creates or reuses a target and a
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

Create a dedicated GMP account for A2VM (named `vulnops`, unchanged since v0.11.0 to keep existing set-ups), with the User role (not Admin):

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
```

A full scan of a few hosts on every TCP port takes hours. The GitLab job timeout (1 h by default)
must be longer than `timeout_minutes`: set it in the client project, **Settings > CI/CD > General
pipelines > Timeout** (e.g. `5h`), and check the runner's own maximum job timeout. If the job is
killed anyway, gvmd goes on scanning: a later run waits for the running scan, or collects the
finished one when it is younger than `reuse_hours`.

List each address once: a host name and the address it resolves to are two targets for the
scanner, and the same machine is then scanned twice.

CI/CD variables of the client project:

| Key | Type | Value |
| --- | --- | --- |
| `VULNOPS_GVM_USER` | Variable | `vulnops` |
| `VULNOPS_GVM_PASSWORD` | Variable, masked, protected | the GMP password |
| `VULNOPS_GVM_CA` | File | `ca.pem` |
| `VULNOPS_GVM_CERT` | File, protected | `client.crt` |
| `VULNOPS_GVM_KEY` | File, protected | `client.key` |

Check the file with `detect plan targets.yaml` (the validate job does it). The daily
`collect` job then runs the scan; it needs no `VULNOPS_SSH_KEY` when the file has no SSH target.

## 5. Scanner host as runner (external scans)

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
     environment = ["VULNOPS_SERVER_URL=https://gitlab.example.org"]
     [runners.docker]
       volumes = ["/cache", "greenbone-community-edition_gvmd_socket_vol:/run/gvmd"]
   ```

   `VULNOPS_SERVER_URL` makes the job fetch the vulnops code by the public URL; the client
   certificate is handed to git through `CI_SERVER_TLS_CERT_FILE` and `CI_SERVER_TLS_KEY_FILE`.

2. In the client project, run the collection there and talk to gvmd over the socket:

   ```yaml
   # .gitlab-ci.yml
   variables:
     VULNOPS_COLLECT_TAG: scan-cloud
   ```

   ```yaml
   # targets.yaml
   openvas:
     gmp: unix:///run/gvmd/gvmd.sock
     hosts: [203.0.113.10, www.example.org]
   ```

   Only `VULNOPS_GVM_USER` and `VULNOPS_GVM_PASSWORD` are needed (no certificates over a socket).

The scanner host then holds a runner token and, while a job runs, a job token: register it on
this project only, and keep client projects with internal data on internal runners.

## How results are read

- One asset per scanned host (IP, host name, OS when the scanner found them); it merges with the
  same host seen by Trivy or dnf (same FQDN, host name or address).
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
