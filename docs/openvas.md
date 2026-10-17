# OpenVAS network scans (Greenbone Community Edition)

vulnops drives a Greenbone scanner (gvmd + OpenVAS) over GMP: it creates or reuses a target and a
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
| A host on the internet (VPS) | Only what the client exposes to the internet | External exposure, a check of the `exposure: internet` declarations |

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

Create a dedicated GMP account for vulnops, with the User role (not Admin):

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
  # timeout_minutes: 240
```

CI/CD variables of the client project:

| Key | Type | Value |
| --- | --- | --- |
| `VULNOPS_GVM_USER` | Variable | `vulnops` |
| `VULNOPS_GVM_PASSWORD` | Variable, masked, protected | the GMP password |
| `VULNOPS_GVM_CA` | File | `ca.pem` |
| `VULNOPS_GVM_CERT` | File, protected | `client.crt` |
| `VULNOPS_GVM_KEY` | File, protected | `client.key` |

Check the file with `vulnops-detect plan targets.yaml` (the validate job does it). The daily
`collect` job then runs the scan; it needs no `VULNOPS_SSH_KEY` when the file has no SSH target.

## How results are read

- One asset per scanned host (IP, host name, OS when the scanner found them); it merges with the
  same host seen by Trivy or dnf (same FQDN, host name or address).
- One finding per host and CVE; the port and the NVT are kept on each observation, with the
  installed and fixed versions when the NVT reports them, and its CVSS v3 vector.
- Left out, and counted: results below the QoD threshold (guesses from banners), log-level
  results, results without a CVE (configuration findings such as weak TLS ciphers).
- The report is parsed with defusedxml (no entity expansion, no external entities): it carries
  strings chosen by the scanned hosts.

## Manual import

Export the report from the web interface (Reports, download, format XML), then:

```bash
vulnops-detect import --client lab --source openvas report.xml --out work/detect
```
