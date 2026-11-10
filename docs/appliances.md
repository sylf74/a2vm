# Appliances and network devices (v0.23.6)

A firewall, a switch, a router or a VPN gateway has no package an SSH collection could list, no EDR
agent and no SBOM. Yet these edge devices are the most exploited and the least scanned. A2VM reads
their exact version (their firmware) where it is known: over SNMP, or from the CMDB. The watch then
matches it against the affected versions of each new CVE record and of the vendor's CSAF advisory,
and names the device with the level of proof **embedded** (embarqué). Design: LLD detection §3.9,
HLD D20.

| Where the version comes from | Connector | Source |
| --- | --- | --- |
| The device itself: sysDescr, sysObjectID, sysName and the vendor's version object | `snmp` of the collector | `snmp` |
| The CMDB: brand, model and IOS version of a NetworkDevice (iTop) | `itop`, nothing to add | `cmdb` |

Neither is a scan: a device seen this way is not counted as scanned, and no finding is made. The
alert names it; the SSVC tables decide (D4).

## 1. Families recognised

| Vendor | Product | CPE | Version read from |
| --- | --- | --- | --- |
| Cisco | IOS, IOS XE, NX-OS, ASA | `cisco:ios`, `cisco:ios_xe`, `cisco:nx-os`, `cisco:adaptive_security_appliance_software` | sysDescr |
| Fortinet | FortiOS | `fortinet:fortios` | `fgSysVersion` (1.3.6.1.4.1.12356.101.4.1.1.0) |
| Palo Alto Networks | PAN-OS | `paloaltonetworks:pan-os` | `panSysSwVersion` (1.3.6.1.4.1.25461.2.1.2.1.1.0) |
| Juniper | Junos OS | `juniper:junos` | sysDescr |
| MikroTik | RouterOS | `mikrotik:routeros` | sysDescr, else `mtxrFirmwareVersion` |
| VyOS, Aruba | VyOS, ArubaOS-CX | `vyos:vyos`, `arubanetworks:arubaos-cx` | sysDescr |

A device of another family keeps its vendor, product and version, without CPE: it goes into the
tenant's applications table, where the LLM proposes its CPE and a validator decides
(`docs/sentinelone.md` §4); once validated, it is matched like the others. A host answering SNMP
(Linux, Windows) is left out: its packages come from SSH or an agent. From the CMDB, a Cisco version
without the family in its name (`17.9.4a` rather than `IOS-XE 17.9.4a`) has no CPE either: IOS and
IOS XE share their version numbers.

## 2. SNMP account

SNMPv3 with authentication and privacy (`authPriv`), a read-only view, on each device. For example
on a Cisco device, with the collector's address:

```text
snmp-server view A2VM-RO system included
snmp-server view A2VM-RO enterprises included
snmp-server group A2VM-RO v3 priv read A2VM-RO access A2VM-COLLECTOR
snmp-server user a2vm-ro A2VM-RO v3 auth sha256 <auth password> priv aes 128 <priv password>
ip access-list standard A2VM-COLLECTOR
 permit 192.0.2.10
```

A2VM asks for four objects at most per device (sysDescr, sysObjectID, sysName, the vendor's version
object): the views `system` and the vendor's subtree are enough. On the collector, each password in
its file, readable by the agent only, without typing it on a command line:

```bash
sudo sh -c 'umask 077; cat > /etc/a2vm/collector/snmp-auth'
```

```bash
sudo sh -c 'umask 077; cat > /etc/a2vm/collector/snmp-priv'
```

```bash
sudo chown 10001:10001 /etc/a2vm/collector/snmp-auth /etc/a2vm/collector/snmp-priv
```

Each command waits for the password: paste it, press Enter, then Ctrl-D. An old device that knows
SNMPv2c only: `version: 2c` and a `community_file` instead.

## 3. Connector on the collector

In `/etc/a2vm/collector/collector.yaml` (`docs/collectors.md` §2):

```yaml
connectors:
  - name: lan-network
    type: snmp
    targets: [192.0.2.1, 192.0.2.64/28, fw01.lab.example]   # addresses, names or networks
    user: a2vm-ro
    auth_password_file: /etc/a2vm/collector/snmp-auth
    priv_password_file: /etc/a2vm/collector/snmp-priv
    # auth_protocol: sha256                  # sha, sha224, sha256, sha384, sha512, md5
    # priv_protocol: aes                     # aes, aes192, aes256, des, 3des, none (authNoPriv)
    # version: 2c                            # with community_file, for old devices
    # community_file: /etc/a2vm/collector/snmp-community
    # exclude: [192.0.2.70]                  # addresses or networks left out
    # port: 161
    # timeout_seconds: 2
    # retries: 1
    # concurrency: 32                        # devices asked at once
```

At most 4096 addresses per connector. Its timer runs before the daily run
(`sudo systemctl enable --now a2vm-collector@lan-network.timer`). In the tenant project,
`collectors.yaml` declares the source: `sources: [..., snmp]`. The journal shows
`snmp: <n> targets, <m> devices, firmware known on <k>`, then `ok   snmp [lan-network]`. A test
without the collector: `detect snmp fetch --config snmp.yaml --tenant lab --out work/detect`.

The CMDB needs nothing new: the `itop` connector reads the NetworkDevice's brand, model and IOS
version since v0.23.6. A device seen both by SNMP and in the CMDB is one asset, with both firmwares
dated: the SNMP reading is the device's own word.

## 4. Matching and levels of proof

At each passage, the watch matches each firmware against the affected blocks of the new records:

| Case | Level |
| --- | --- |
| The version is in an affected range of the record or of the vendor's CSAF advisory | embedded (embarqué) |
| The vendor lists its affected versions one by one (Cisco) and the version is not in the list | not named |
| The record names the product without deciding the version (the vendor has not published yet) | possible, "version not decided" |
| A firmware without CPE whose row of the applications table is only proposed | possible, "mapping to validate" |

The records name these products their own way (`Cisco IOS XE Software`, `Junos OS`): a block matches
by its CPE, else by its vendor and its product less the vendor and `Software`. The CSAF advisory of a
vendor (catalogue of the watch, kind `csaf`) carries its product status: the versions known affected
(exact or `vers:` ranges) and those fixed. When the watch reads such an advisory, its status replaces
the record's CNA block for the same product, often still without versions. The catalogue has
`cisco-csaf` disabled: enable it (`enabled: true`, and the RSS source `cisco` disabled) to have Cisco's
versions from its advisories; Fortinet and Palo Alto Networks give theirs in their CVE records.

In the alert sheet the device appears with its firmware (`Fortinet FortiOS 7.2.8`), the fixed version
when the range gives it, the source (`firmware reported (snmp, <date>)`) and the proof `embedded`.

## 5. When the connector fails

| Journal | Cause | Remedy |
| --- | --- | --- |
| `cannot read /etc/a2vm/collector/snmp-auth` | A password file missing | §2 |
| `snmp: <n> targets, 0 devices` | Firewall (UDP 161), ACL of the device, wrong user or passwords | `snmpget -v3 -l authPriv -u a2vm-ro -a SHA-256 -A … -x AES -X … <ip> 1.3.6.1.2.1.1.1.0` from the collector |
| `firmware known on 0` | Devices of families not recognised, or a view without the vendor's subtree | §1; the view `enterprises` |
| `pysnmp is missing` | An image older than v0.23.6 | `detect:v0.23.6` |

Not verified yet on real devices: the sysDescr of each family and the vendors' version objects, taken
from their MIBs. The first reading tells: the counts in the journal, the hosts and their OS in the
chat (`get_asset`).
