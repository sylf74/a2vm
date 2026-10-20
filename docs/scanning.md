# Read-only scanner collection

The `collect` job of a client pipeline connects over SSH from the runner to each target listed in
the `targets.yaml` of the client project, runs one read-only command, and imports its output:

| Method | Hosts | Command run on the target | Needs |
| --- | --- | --- | --- |
| `trivy` | Ubuntu, Debian, Rocky/Alma/RHEL/CentOS 8–9 | `nice -n 19 ionice -c3 trivy rootfs --quiet --timeout 15m --format json --scanners vuln --pkg-types os /` | Trivy installed |
| `trivy` + `images` | Docker hosts | `... trivy image --quiet --timeout 30m --format json --scanners vuln --pkg-types os,library --skip-dirs <CUDA dirs> <image>` | Trivy, access to the Docker socket |
| `dnf-updateinfo` | Rocky/RHEL 10 (not covered by Trivy) | `nice -n 19 ionice -c3 dnf -q updateinfo list --security --with-cve` | nothing |

Why it is not intrusive:

- the commands only read: Trivy reads the OS package database (`--pkg-types os` scans only
  known files, it does not walk the file system, so data pools and VM disks are never read);
  dnf lists the security advisories that apply to the installed packages;
- nothing is installed, changed or exploited on the targets; there is no network scan;
- both run at the lowest CPU and I/O priority; a scan takes seconds to a minute per host;
- the SSH account is unprivileged and dedicated, and its key is accepted only from the runner.

Coverage limits: Windows servers and appliances (routers, firewalls, NAS, home automation...) are
not covered by these methods. They are declared in the client profile and matched against CVE
records by product and version; a network scanner (OpenVAS) or a Windows collector comes next.

At a client, active collection requires the client's written authorization; by default A2VM
ingests the outputs of the client's own scanners (`detect import`).

Addresses and host names below are examples (RFC 5737, `lab.example`); the runner is `192.0.2.104`.

## 1. Create the scan key (once per client project, on the runner)

With your usual admin account (no root needed). The key is only kept there long enough to fill the
GitLab variable and to run the manual test of step 3:

```bash
ssh-keygen -t ed25519 -N "" -C "vulnops-scan-<client>" -f ~/vulnops_scan
cat ~/vulnops_scan.pub        # public key, for step 2
```

In GitLab, **client project** (e.g. `vulnops/clients/<client>`): **Settings > CI/CD > Variables > Add variable**

- Type: **File** · Key: `A2VM_SSH_KEY` · Value: the content of `~/vulnops_scan` (private key)
- Protect variable: **checked** — only pipelines of protected branches (`main`, the schedule) get it
- Visibility: **Visible** — a private key spans several lines and GitLab cannot mask it; the job
  never prints it, and the key only opens an unprivileged account, from the runner's address only

One key per client: a key never opens the hosts of another client.

## 2. Prepare each target (once per host)

Dedicated unprivileged account, key restricted to the runner's address:

```bash
sudo useradd --create-home --shell /bin/bash vulnops
sudo install -d -m 700 -o vulnops -g vulnops /home/vulnops/.ssh
echo 'from="192.0.2.104",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... vulnops-scan-<client>' \
  | sudo tee /home/vulnops/.ssh/authorized_keys
sudo chown vulnops:vulnops /home/vulnops/.ssh/authorized_keys && sudo chmod 600 /home/vulnops/.ssh/authorized_keys
```

Paste the real public key in place of `ssh-ed25519 AAAA...`, on one line, and check it with
`sudo ssh-keygen -lf /home/vulnops/.ssh/authorized_keys`: it must print the same fingerprint as
`ssh-keygen -lf ~/vulnops_scan.pub` on the runner.

On hosts with SELinux (Rocky, RHEL): `sudo restorecon -R /home/vulnops/.ssh`.

On the runner itself, also accept connections from the host and from the Docker bridge: a CI job
reaching its own host arrives from 172.17.x.x, and a local test from 127.0.x.x (Ubuntu resolves
the host's own name to 127.0.1.1 in `/etc/hosts`): `from="192.0.2.104,127.0.0.0/8,172.17.0.0/16",...`.

### Hosts scanned with Trivy

Ubuntu / Debian (official Aqua Security repository):

```bash
sudo apt-get install -y wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install -y trivy
```

Rocky / Alma / RHEL / CentOS 8–9:

```bash
cat << 'EOF' | sudo tee /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
EOF
sudo dnf install -y trivy
```

On an end-of-life release whose mirrors are gone (CentOS Linux 8), only enable the Trivy repository:
`sudo dnf --disablerepo='*' --enablerepo=trivy install -y trivy`. Trivy flags such hosts as
"end of support" in the asset's OS: they no longer get fixes, which matters more than any single CVE.

Trivy downloads its vulnerability database (from GitHub's container registry) into the scan
account's cache on first run and refreshes it when needed: the targets need outbound HTTPS.

Images (`images:` in the targets file): the scan account must reach the Docker socket
(`sudo usermod -aG docker vulnops`). That group is root-equivalent on the host: only do it on a
host where it is acceptable, otherwise drop the `images` entry.

### Hosts scanned with dnf (Rocky / RHEL 10)

Nothing to install. To keep the advisory metadata fresh without the scan account downloading it,
make sure `dnf-makecache.timer` is active: `systemctl status dnf-makecache.timer`.

## 3. Test by hand from the runner

```bash
for h in node01 node02; do
  ssh -i ~/vulnops_scan -o BatchMode=yes -o StrictHostKeyChecking=accept-new vulnops@$h.lab.example \
    '. /etc/os-release; echo "$PRETTY_NAME | trivy: $(command -v trivy >/dev/null && echo yes || echo no)"'
done
```

Then delete the private key from the runner (`rm ~/vulnops_scan ~/vulnops_scan.pub`): CI jobs get
it from the GitLab variable. Run the client pipeline (**Build > Pipelines > Run pipeline**): the
`collect` job lists each target and any error; the detection files (`work/detect/`) are kept 7 days
in the job artifacts.

## Network scans

For hosts where no account can be created (appliances, BMC, network devices) or to see what is
reachable from a given network position, add an OpenVAS scan to the targets file: `docs/openvas.md`.
