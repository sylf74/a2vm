# Collectors and the detection service (v0.13.0, HLD D15 step 2)

A **collector** runs near a client network: it scans the targets (read-only SSH, OpenVAS) or
imports scanner exports, and **pushes** each detection to the **detection service** of the
tenant, in the cluster. The daily run then reads the latest detection of each source from the
service instead of collecting itself (`collect.mode: intake`). The cluster never connects to a
client machine; a target allows only the collector of its network. Design: LLD detection §8.

```
client network                                      cluster, namespace a2vm-<tenant>
┌──────────────────────────────┐                    ┌───────────────────────────────────────┐
│ targets ◀─SSH─ collector     │── HTTPS push ─────▶│ ingress (collectors' addresses only)  │
│ OpenVAS ◀─GMP─ (detect agent,│   token per        │   └▶ a2vm-<tenant>-detect (detect     │
│                systemd timer)│   collector        │       serve, volume of detections)    │
└──────────────────────────────┘                    │ a2vm-<tenant>-daily ── detect fetch ──┘
                                                    └───────────────────────────────────────┘
```

Host names and addresses below are examples.

## 1. Declare the collectors (tenant project)

`collectors.yaml`, next to `client.yaml`:

```yaml
collectors:
  - id: lab-lan                  # lower case, digits, dashes
    description: LAN collector (collector01.lab.example)
    sources: [trivy, dnf-updateinfo, openvas]
    max_age_hours: 30            # older detections are refused, at push and at fetch
```

A tenant with several networks declares one collector per network; two collectors may push the
same source, and the daily run merges their latest detections. `validate` checks the file
(`detect collectors`), including that the client id of `client.yaml` is the tenant id (the
project name in lower case, as `deploy-k8s` names the tenant).

CI/CD variables of the tenant project:

| Key | Value | Options |
| --- | --- | --- |
| `A2VM_COLLECTOR_TOKEN_<ID>` | The collector's token (id in upper case, dashes as underscores: `A2VM_COLLECTOR_TOKEN_LAB_LAN`) | Masked, protected |
| `A2VM_COLLECTOR_TOKEN_<ID>_NEXT` | A second token during a rotation (section 4) | Masked, protected |
| `A2VM_INTAKE_HOST` | Host name of the push endpoint, e.g. `detect-lab.apps.example.org`; without it, no ingress | Visible |
| `A2VM_INTAKE_ALLOW` | Addresses of the collectors, CIDR, comma-separated, e.g. `192.0.2.10/32` | Visible |
| `A2VM_INTAKE_INGRESS_CLASS`, `A2VM_INTAKE_TLS_SECRET` | Optional: ingress class, Secret of the host's certificate | Visible |
| `A2VM_COLLECT_MODE` | Optional, default `intake`; `local` keeps the daily run collecting itself while the collectors are tried side by side | Visible |

The token is made on the collector (section 2) and pasted from there into the variable: a token
is 32 to 512 characters without spaces. On the next push to the default branch, `deploy-k8s`:

- writes the digests of the tokens to the Secret `a2vm-intake` (the service keeps only digests);
- keeps the read token of the daily run (key `detect-read-token` of the Secret `a2vm-tenant`), or
  makes one at the first deployment;
- deploys the service (`a2vm-<tenant>-detect`), its volume, the ingress and the network policy,
  and the CronJob in `intake` mode. The job log lists each collector with "token set" or "no
  token", never a value.

The allow-list works only if the ingress controller sees the collectors' real addresses (no
source NAT in front of it). With another controller than ingress-nginx, set the chart value
`intake.ingress.nginx: false` and put that controller's allow-list in `intake.ingress.annotations`.

## 2. Install a collector (VM near the network)

A VM that reaches the targets and the push endpoint: 2 vCPU, 2 GB, 20 GB, Podman, outbound HTTPS
only (no inbound port). The scanners run on the targets (Trivy, dnf) or on the OpenVAS host; the
collector only drives them. The examples use Rocky Linux and the image of the release.

```bash
sudo dnf install -y podman openssl
sudo install -d -m 0750 -o 10001 -g 10001 /etc/a2vm/collector /etc/a2vm/collector/ssh \
  /var/lib/a2vm /var/lib/a2vm-ssh
# The collector's token: made here, readable by the agent only, then pasted into GitLab.
sudo sh -c 'umask 077; openssl rand -hex 32 > /etc/a2vm/collector/token'
sudo chown 10001:10001 /etc/a2vm/collector/token
sudo cat /etc/a2vm/collector/token   # once, to copy into A2VM_COLLECTOR_TOKEN_<ID>
```

The scan key of the read-only account goes to `/etc/a2vm/collector/ssh/scan_key` (owner 10001,
mode 0600), the targets file of the network to `/etc/a2vm/collector/targets.yaml` with
`identity_file: /etc/a2vm/collector/ssh/scan_key`. Then `/etc/a2vm/collector/collector.yaml`:

```yaml
collector: lab-lan                         # as declared in collectors.yaml
tenant: lab
service: https://detect-lab.apps.example.org
token_file: /etc/a2vm/collector/token
# ca_file: /etc/a2vm/collector/ca.pem      # CA of the endpoint's certificate, if private
work: /var/lib/a2vm/work
spool: /var/lib/a2vm/spool
connectors:
  - name: lan                              # SSH (trivy, dnf-updateinfo) and OpenVAS
    type: targets
    targets: /etc/a2vm/collector/targets.yaml
    ssh: true
    openvas: true
  # - name: trivy-drop                     # Trivy exports dropped by another tool
  #   type: file-import
  #   source: trivy                        # trivy (.json), dnf-updateinfo (.txt), openvas (.xml)
  #   folder: /var/lib/a2vm/import/trivy
```

The image, with the group deploy token of the cluster (`docs/kubernetes.md` §1), the password read
from a file:

```bash
sudo podman login registry.example.org -u "$(cat registry-user.txt)" --password-stdin < registry-password.txt
sudo podman pull registry.example.org/vulnops/a2vm/detect:v0.13.0
```

One systemd service and timer per connector, `/etc/systemd/system/a2vm-collector@.service`:

```ini
[Unit]
Description=A2VM collector, connector %i
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
# 3: partial (a scan failed, or a push kept in the spool for the next run): a warning in the journal.
SuccessExitStatus=3
TimeoutStartSec=6h
ExecStart=/usr/bin/podman run --rm --name a2vm-collector-%i --user 10001:10001 \
  -v /etc/a2vm/collector:/etc/a2vm/collector:ro,Z \
  -v /var/lib/a2vm:/var/lib/a2vm:Z \
  -v /var/lib/a2vm-ssh:/home/a2vm/.ssh:Z \
  registry.example.org/vulnops/a2vm/detect:v0.13.0 \
  detect agent run --config /etc/a2vm/collector/collector.yaml --connector %i
```

`/etc/systemd/system/a2vm-collector@.timer` (before the daily run of the cluster, 05:45 by
default; an OpenVAS scan can take hours, so start it early):

```ini
[Unit]
Description=A2VM collector, connector %i, daily

[Timer]
OnCalendar=*-*-* 01:30:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now a2vm-collector@lan.timer
sudo systemctl start a2vm-collector@lan.service      # a first run now
journalctl -u a2vm-collector@lan.service -f
```

Another schedule for one connector: `sudo systemctl edit a2vm-collector@trivy-drop.timer`. Host
keys of the targets are accepted on first use and kept in `/var/lib/a2vm-ssh`. A new release:
change the tag in the unit and pull the image.

## 3. Check

The journal shows one line per push: `lab [lab-lan]: pushed trivy -> <id>`. On the cluster side,
the service's log has one line per push accepted or refused, with the reason. The state of each
collector (last push per source, age, staleness, last refusal) is read inside the cluster with
the read token, from a workstation with access to the namespace:

```bash
NS=a2vm-lab
kubectl -n $NS port-forward svc/a2vm-lab-detect 8080:8080 &
( umask 077; printf 'Authorization: Bearer %s\n' \
    "$(kubectl -n $NS get secret a2vm-tenant -o jsonpath='{.data.detect-read-token}' | base64 -d)" > ~/.a2vm-read )
curl -s -H @"$HOME/.a2vm-read" http://127.0.0.1:8080/v1/tenants/lab/collectors; rm -f ~/.a2vm-read
```

The daily run's first step (`collect`) prints one line per source written, and a warning per
source missing or older than its `max_age_hours`; with no detection at all, it stops.

## 4. Rotate, move, remove

- **Rotate a token**: make a new token on the collector, set it as `A2VM_COLLECTOR_TOKEN_<ID>_NEXT`
  and push (both tokens are valid), switch the collector's token file, then move the new token to
  `A2VM_COLLECTOR_TOKEN_<ID>`, delete `_NEXT` and push again.
- **Revoke**: delete the variable (or the collector from `collectors.yaml`) and push: its token
  no longer matches any digest.
- **Move a collector**: change its address in `A2VM_INTAKE_ALLOW`, push, then install it on the new
  VM with the same token.

## 5. When something goes wrong

| Situation | Behaviour |
| --- | --- |
| Service unreachable, 429 or 5xx | The detection is kept in `/var/lib/a2vm/spool` (newest per source) and pushed at the next run; exit 3 |
| Push refused (401 token, 403 source not declared, 422 another client or too old) | Error in the journal and in the service's log, nothing stored; a spooled detection refused this way is set aside as `<source>.json.rejected` |
| Detection older than `max_age_hours` at the daily run | Left out with a warning; the run goes on with the other sources |
| No detection at all | The daily run stops at `collect`: no report of an estate without its scanners |
| Address not in the allow-list | 403 from the ingress, before the service |
