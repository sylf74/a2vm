# Wazuh's software inventory (v0.23.1)

Wazuh's agents list the software installed on each machine (syscollector). A2VM reads that
inventory as a source of components (`wazuh`): one host per agent, every package with its
distribution and its source package. The watch then names the hosts that hold an affected version
of a new CVE, as for the packages listed over SSH (`docs/alerts.md`, HLD D20). A2VM never changes
anything in Wazuh, and does not read Wazuh's own vulnerability detection. Design: LLD detection
§3.6, LLD triage §14.7.

## 1. Which API

| `api` | Where | For |
| --- | --- | --- |
| `indexer` (default) | The Wazuh indexer, `https://<indexer>:9200` | Recent versions with the global state indices `wazuh-states-inventory-system-*` and `wazuh-states-inventory-packages-*`: every agent in a few requests |
| `manager` | The manager's API, `https://<manager>:55000` | Every 4.x version: agent by agent, slower on a large estate |

The check of §2 tells which: a count is the indexer's way; `index_not_found_exception` (404)
means a version without the inventory indices, use `api: manager`.

## 2. Read-only account

**Indexer.** In the Wazuh dashboard, Indexer management > Security: a role `a2vm-inventory` with
the index permissions `read` on `wazuh-states-inventory-*` (no cluster permission), an internal
user `a2vm-inventory` mapped to that role. Its password is made on the collector, stored in a file
readable by the agent only, and pasted once into the dashboard:

```bash
sudo sh -c 'umask 077; openssl rand -base64 24 > /etc/a2vm/collector/wazuh-password'
sudo chown 10001:10001 /etc/a2vm/collector/wazuh-password
```

Check from the collector (a count of the packages):

```bash
sudo curl -sS --cacert /etc/a2vm/collector/wazuh-ca.pem -u "a2vm-inventory:$(sudo cat /etc/a2vm/collector/wazuh-password)" "https://wazuh-indexer.lab.example:9200/wazuh-states-inventory-packages-*/_count"
```

**Manager.** In the Wazuh dashboard, Server management > Security: a user `a2vm-inventory` with
the role `readonly`. Check from the collector (a token is expected):

```bash
sudo curl -sS --cacert /etc/a2vm/collector/wazuh-ca.pem -u "a2vm-inventory:$(sudo cat /etc/a2vm/collector/wazuh-password)" -X POST "https://wazuh.lab.example:55000/security/user/authenticate"
```

## 3. Connector on the collector

In `/etc/a2vm/collector/collector.yaml` (`docs/collectors.md` §2):

```yaml
connectors:
  - name: lan-wazuh
    type: wazuh
    url: https://wazuh-indexer.lab.example:9200
    api: indexer                                  # or manager, url https://wazuh.lab.example:55000
    user: a2vm-inventory
    password_file: /etc/a2vm/collector/wazuh-password
    ca_file: /etc/a2vm/collector/wazuh-ca.pem      # CA of the Wazuh certificates, if private
    # page_size: 2000                             # documents per request
    # timeout_seconds: 120
```

Its timer runs before the daily run (`sudo systemctl enable --now a2vm-collector@lan-wazuh.timer`).
In the tenant project, `collectors.yaml` declares the source with the collector's others:
`sources: [trivy, dnf-updateinfo, openvas, cmdb, wazuh]`. The journal shows
`wazuh: <n> agents, packages listed on <m> (indexer)`, then `ok   wazuh [<url>]: <n> agents`. A
test without the collector: `detect wazuh fetch --config wazuh.yaml --tenant lab --out work/detect`.

## 4. What A2VM does with it

- An agent becomes a host joined to the other observations of the same machine by host name, FQDN
  or address: the components of Wazuh and those listed over SSH stay side by side, each with its
  source and date (`find_component` in the chat shows both).
- A disconnected agent keeps its last inventory, dated by its last keep-alive; an agent never
  connected is left out.
- Wazuh is an inventory, not a scan: it does not count as a scan of the host in the coverage.
- Linux packages (rpm, deb) are matched as soon as they are read. Windows and macOS software keeps
  its publisher (since v0.23.3) and is matched through the tenant's applications table, as the
  applications of SentinelOne (`docs/sentinelone.md` §4).

## 5. When the connector fails

| Journal | Cause | Remedy |
| --- | --- | --- |
| `Wazuh indexer not reached` | Address, DNS, firewall, certificate not trusted | `curl` of §2 from the collector; `ca_file` |
| `refused the user 'a2vm-inventory' (401)` | Wrong user or password | The password file and the user |
| `refused the user … (403)` | The role does not read the indices | Index permission `read` on `wazuh-states-inventory-*` |
| `no index 'wazuh-states-inventory-system-*'` | A version without the inventory indices, or no agent yet | `api: manager` |
| `password_file … is empty` | The file is missing or empty | Its path in `collector.yaml` |
