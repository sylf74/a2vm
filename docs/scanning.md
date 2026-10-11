# Read-only scanner collection (lab)

The `collect` job connects over SSH from the runner to each target listed in
`config/targets/<client>.yaml`, runs one read-only command, and imports its output:

| Method | Hosts | Command run on the target | Needs |
| --- | --- | --- | --- |
| `trivy` | Ubuntu, Debian, Rocky/Alma/RHEL 8–9 | `nice -n 19 ionice -c3 trivy rootfs --quiet --format json --scanners vuln --pkg-types os /` | Trivy installed |
| `trivy` + `images` | Docker hosts | `... trivy image --quiet --format json --scanners vuln --pkg-types os,library <image>` | Trivy, access to the Docker socket |
| `dnf-updateinfo` | Rocky/RHEL 10 (not covered by Trivy) | `nice -n 19 ionice -c3 dnf -q updateinfo list --security --with-cve` | nothing |

Why it is not intrusive:

- the commands only read: Trivy reads the OS package database (`--pkg-types os` scans only
  known files, it does not walk the file system, so ZFS pools and VM disks are never read);
  dnf lists the security advisories that apply to the installed packages;
- nothing is installed, changed or exploited on the targets; there is no network scan;
- both run at the lowest CPU and I/O priority; a scan takes seconds to a minute per host;
- the SSH account is unprivileged and dedicated, and its key is accepted only from the runner.

Coverage limits: Windows (Active Directory, Exchange) and appliances (VyOS, NAS, Home Assistant)
are not covered by these methods. They are declared in the client profile and matched against
CVE records by product and version; a network scanner (OpenVAS) or a Windows collector comes next.

## 1. Create the scan key (once, on the runner)

With your usual admin account (no root needed). The key is only kept there long enough to fill the
GitLab variable and to run the manual test of step 3:

```bash
ssh <admin>@192.0.2.104
ssh-keygen -t ed25519 -N "" -C "vulnops-scan" -f ~/vulnops_scan
cat ~/vulnops_scan.pub        # public key, for step 2
```

In GitLab, project `vulnops`: **Settings > CI/CD > Variables > Add variable**

- Type: **File** · Key: `VULNOPS_SSH_KEY` · Value: the content of `~/vulnops_scan` (private key)
- Protect variable: **checked** — only pipelines of protected branches (`main`, the schedule) get it
- Visibility: **Visible** — a private key spans several lines and GitLab cannot mask it; the job
  never prints it, and the key only opens an unprivileged account, from the runner's address only

Keep `~/vulnops_scan` on the runner until the manual test of step 3, then delete it.

## 2. Prepare each target (once per host)

Dedicated unprivileged account, key restricted to the runner's address:

```bash
sudo useradd --create-home --shell /bin/bash vulnops
sudo install -d -m 700 -o vulnops -g vulnops /home/vulnops/.ssh
echo 'from="192.0.2.104",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... vulnops-scan' \
  | sudo tee /home/vulnops/.ssh/authorized_keys
sudo chown vulnops:vulnops /home/vulnops/.ssh/authorized_keys && sudo chmod 600 /home/vulnops/.ssh/authorized_keys
```

On Rocky hosts with SELinux: `sudo restorecon -R /home/vulnops/.ssh`.

### Hosts scanned with Trivy

Ubuntu / Debian (official Aqua Security repository):

```bash
sudo apt-get install -y wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
  | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install -y trivy
```

Rocky 9 (Node00):

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

Trivy downloads its vulnerability database (from GitHub's container registry) into the scan
account's cache on first run and refreshes it when needed: the targets need outbound HTTPS.

Images (`images:` in the targets file): the scan account must reach the Docker socket
(`sudo usermod -aG docker vulnops`). That group is root-equivalent on the host: only do it on a
host where it is acceptable (here `poc-llm01`), otherwise drop the `images` entry.

### Hosts scanned with dnf (Rocky 10)

Nothing to install. To keep the advisory metadata fresh without the scan account downloading it,
make sure `dnf-makecache.timer` is active: `systemctl status dnf-makecache.timer`.

## 3. Test by hand from the runner

```bash
ssh -i ~/vulnops_scan vulnops@edge01.lab.example 'dnf -q updateinfo list --security --with-cve | head'
ssh -i ~/vulnops_scan vulnops@gitlab.lab.example 'trivy rootfs --quiet --format json --scanners vuln --pkg-types os / | head -c 300'
```

Then delete the private key from the runner (`rm ~/vulnops_scan ~/vulnops_scan.pub`): CI jobs get
it from the GitLab variable. Run a pipeline (`TRIAGE_MODE=manual`): the `collect` job lists each target and any error,
and the raw outputs are kept in the `work/scans/` artifact for 7 days.
