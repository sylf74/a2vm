# Cyberwatch's scans (v0.23.5)

A tenant that already runs Cyberwatch need not be scanned again: NGVM reads what Cyberwatch found.
One host per Cyberwatch asset, its packages as components, and one finding per CVE still open on the
asset, with the version found and the version that fixes it. It is a scan (source `cyberwatch`): the
asset counts as scanned, and its findings are triaged like those of OpenVAS. NGVM never changes
anything in Cyberwatch. Design: LLD detection §3.8.

## 1. API keys

Cyberwatch's documentation asks for the keys of a user of role **Administrator** to use the API. Make
a user `ngvm-api` for NGVM alone, limited to the tenant's groups, and generate its keys (Profile >
API Keys). On the collector, paste each key into its file, readable by the agent only, without typing
it on a command line:

```bash
sudo sh -c 'umask 077; cat > /etc/ngvm/collector/cyberwatch-access-key'
```

```bash
sudo sh -c 'umask 077; cat > /etc/ngvm/collector/cyberwatch-secret-key'
```

```bash
sudo chown 10001:10001 /etc/ngvm/collector/cyberwatch-access-key /etc/ngvm/collector/cyberwatch-secret-key
```

Each command waits for the key: paste it, press Enter, then Ctrl-D. Check from the collector:

```bash
sudo sh -c 'curl -sS --user "$(cat /etc/ngvm/collector/cyberwatch-access-key):$(cat /etc/ngvm/collector/cyberwatch-secret-key)" "https://cyberwatch.lab.example/api/v3/vulnerabilities/servers?page=1&per_page=1"' | head -c 400
```

An asset expected. A 404 means another path in this version of Cyberwatch: `/api/v3/servers`, or
the one of its API documentation (`https://<master>/api/v3/docs`), as `assets_path` and `asset_path`.

A 403 on every path, even `/api/v3/ping`, before any key is checked: a reverse proxy in front of
the master asks for a client certificate (v0.23.17). It says so in the TLS handshake:

```bash
openssl s_client -connect cyberwatch.lab.example:443 -servername cyberwatch.lab.example </dev/null 2>/dev/null | grep -A8 'Acceptable client certificate CA names'
```

Ask for a service certificate (`clientAuth`) of one of the CAs listed, for the collector, then put
it and its key next to the API keys, owned by the agent, the key readable by it only:

```bash
sudo chown 10001:10001 /etc/ngvm/collector/cyberwatch-client.pem /etc/ngvm/collector/cyberwatch-client.key
sudo chmod 0600 /etc/ngvm/collector/cyberwatch-client.key
sudo sh -c 'curl -sS --cert /etc/ngvm/collector/cyberwatch-client.pem --key /etc/ngvm/collector/cyberwatch-client.key --user "$(cat /etc/ngvm/collector/cyberwatch-access-key):$(cat /etc/ngvm/collector/cyberwatch-secret-key)" https://cyberwatch.lab.example/api/v3/ping'
```

## 2. Connector on the collector

In `/etc/ngvm/collector/collector.yaml` (`docs/collectors.md` §2):

```yaml
connectors:
  - name: lan-cbw
    type: cyberwatch
    url: https://cyberwatch.lab.example
    access_key_file: /etc/ngvm/collector/cyberwatch-access-key
    secret_key_file: /etc/ngvm/collector/cyberwatch-secret-key
    # groups: [Production, DMZ]                       # only the assets of these Cyberwatch groups
    # include_ignored: false                          # the CVEs ignored in Cyberwatch, left out by default
    # ca_file: /etc/ngvm/collector/ca.pem             # a private CA
    # cert_file: /etc/ngvm/collector/cyberwatch-client.pem   # behind a reverse proxy asking for a
    # key_file: /etc/ngvm/collector/cyberwatch-client.key    # client certificate: both (v0.23.17)
    # page_size: 100                                  # assets per page, 1 to 500
    # assets_path: /api/v3/vulnerabilities/servers    # the list of the assets
    # asset_path: /api/v3/vulnerabilities/servers/{id}  # one asset with its CVEs, packages, updates
```

**A master shared between several perimeters (customers, entities): `groups` is required.**
Without it, the connector reads every asset the API user sees, and the tenant gets the assets and
the CVEs of the others in its triage, its reports and its tickets. Limit the API user to the
tenant's groups in Cyberwatch, and name them in `groups` too. Without `groups`, the journal warns
when the assets are in more than one group: `WARN cyberwatch: no groups in the connector and the
assets are in <n> groups`. A large master read whole may also go over what the detection service
takes (200 MiB uncompressed, about 450 assets with their CVEs on a real master): the push is refused
with `push refused (413)` and the size; `groups` again.

Its timer runs before the daily run (`sudo systemctl enable --now ngvm-collector@lan-cbw.timer`). In
the tenant project, `collectors.yaml` declares the source: `sources: [..., cyberwatch]`. The journal
shows `cyberwatch: <n> assets, <m> open CVEs, components on <k>`, then `ok   cyberwatch [<url>]`. A
test without the collector: `detect cyberwatch fetch --config cbw.yaml --tenant lab --out work/detect`.

## 3. What NGVM keeps

| Cyberwatch | NGVM |
| --- | --- |
| Asset name, addresses, OS, groups | Host with `hostname`, `fqdn`, `ips`, `os`, attribute `cyberwatch_groups`; merged with the same host seen by SSH, OpenVAS, the CMDB or an EDR |
| Packages (else the current versions of the updates) | Components of source `cyberwatch`; rpm and deb matched against the distributions' advisories, the others through the applications table (`docs/sentinelone.md` §4) |
| CVE active, not fixed, not ignored | A finding: package, version found, target version of the update, Cyberwatch's level |
| CVE fixed in Cyberwatch | No finding: closed at the next run, as for a scan that no longer sees it |
| Cyberwatch's prioritisation, scores | Not used: the SSVC tables of NGVM decide (D4) |

## 4. When the connector fails

| Journal | Cause | Remedy |
| --- | --- | --- |
| `Cyberwatch not reached` | Address, firewall, certificate | `curl` of §1 from the collector; `ca_file` |
| `Cyberwatch refused the API keys (401)` / `(403)` | Wrong keys, a user without access to the assets, or a reverse proxy asking for a client certificate | New keys; the user's role and groups; `cert_file` and `key_file` (§1) |
| `push refused (413)` | The detection is over 200 MiB: a master read whole | `groups` (§2) |
| `Cyberwatch has no /api/...` | Another path in this version | `assets_path`, `asset_path` (§1) |
| `answered something else than JSON` | `url` is not the master (a sign-in page) | The master's address, without `/api` |
| `… is empty` | A key file missing or empty | §1 |

Not verified yet on a real master: the paths and field names, taken from the integrations published
for Cyberwatch 13. The first reading tells: the counts in the journal, the hosts in the chat
(`get_asset`), the findings of source `cyberwatch` after the next daily run.
