# The tenant's CMDB (iTop) and the scan coverage (v0.19.0)

The tenant's CMDB says what exists. A2VM reads it as a detection source (`cmdb`) through a
connector of the collector, takes from it the business criticality and the owner of each asset,
and compares it with what the scanners saw: each host gets a **scan coverage** state. A2VM never
writes to the CMDB: the connector sends `core/get` only; the hosts missing from the CMDB are given
as a file a person imports. Design: LLD detection §3.5, LLD triage §14.3 and §14.6.

## 1. iTop

iTop 3.2 (tested with 3.2.3), the configuration management modules, and for the connected
objects (cameras, TVs, media players, energy meters...) the extension `deploy/itop/a2vm-iot-device`
(class `IoTDevice`, `deploy/itop/README.md`). Each machine is a configuration item of its class
(`Server`, `VirtualMachine`, `Hypervisor`, `NetworkDevice`, `PC`, `Printer`, `NAS`, `IoTDevice`...),
in production, with:

| Field | Used by A2VM for |
| --- | --- |
| Name | Joining the scanned host: a host name (`web01`) or an FQDN (`web01.lab.example`); another name (`Camera garden`) joins by address only |
| Management IP, network interfaces | Joining the scanned host by address |
| Status | Coverage: `production` is expected to be scanned; `implementation`, `stock`, `obsolete` are not, and an obsolete item still seen is "retired but alive" |
| Business criticality | SSVC Mission Prevalence: high → essential, medium → support, low → minimal |
| Contacts | Owner: the first contact by name, else the organisation |

## 2. Read-only account

A local account of iTop (a service account, not a person of the directory), e.g. `a2vm-cmdb`,
with the profiles **REST Services User** (the API) and **Document author** (on iTop 3.2 every
profile reads all classes and differs by what it writes: this one writes documents only, never a
configuration item), allowed organisation: the tenant's. Its password is made on the collector,
stored in a file readable by the agent only, and pasted once into iTop. Check from the collector:

```bash
sudo curl -sS --cacert /etc/a2vm/collector/ca.pem https://itop.lab.example/webservices/rest.php?version=1.3 -d auth_user=a2vm-cmdb --data-urlencode auth_pwd@/etc/a2vm/collector/itop-password --data-urlencode 'json_data={"operation":"core/get","class":"FunctionalCI","key":"SELECT FunctionalCI","output_fields":"name,finalclass"}'
```

`"code":0` is expected.

## 3. Connector on the collector

In `/etc/a2vm/collector/collector.yaml` (`docs/collectors.md` §2):

```yaml
connectors:
  - name: lan-cmdb
    type: itop
    url: https://itop.lab.example
    user: a2vm-cmdb
    password_file: /etc/a2vm/collector/itop-password
    ca_file: /etc/a2vm/collector/ca.pem     # CA of the iTop certificate, if private
    organization: Lab                       # optional: the items of this organisation only
    # classes: [PhysicalDevice, VirtualDevice]        default: every subclass
    # exclude_classes: [Rack, Enclosure, PowerConnection, PowerSource, PDU, Farm]
```

Its timer runs before the daily run (`sudo systemctl enable --now a2vm-collector@lan-cmdb.timer`,
then `sudo systemctl edit a2vm-collector@lan-cmdb.timer` for the time). In the tenant project,
`collectors.yaml` declares the source: `sources: [trivy, dnf-updateinfo, openvas, cmdb]`. The
journal shows `cmdb: PhysicalDevice: <n> items`, `cmdb: VirtualDevice: <n> items`, then
`ok   cmdb [https://itop.lab.example]: <n> items`. A test without the collector:
`detect cmdb fetch --config itop.yaml --tenant lab --out work/detect`.

## 4. Coverage

The daily run's step `assets` prints `coverage with CMDB, <covered>/<in production> covered
(<share>), gaps: …`. Each host is in one state:

| State | Meaning | What to do |
| --- | --- | --- |
| `covered` | In production, every expected means saw it within `stale_days` (7) | — |
| `partial` | Scanned lately, but a means its class expects is missing (a server without Trivy nor dnf) | Add it to the targets of the missing scanner |
| `stale` | Its last scan is older than `stale_days` | Check the collector and the target (host off, account refused) |
| `never-scanned` | In production, no scan has seen it | Add it to the targets, or check its name and address in the CMDB |
| `not-scannable` | In production, no address nor host name | Give it a management IP in the CMDB |
| `not-in-cmdb` | Scanned, but no item of the CMDB is this host | Create its item (§6), or fix the name or the address of the existing one |
| `retired-but-alive` | Obsolete or in stock in the CMDB, still seen | Retire the machine, or correct its status |
| `not-expected` | Being implemented, in stock or obsolete | — |

Means expected per class, in `client.yaml` (a class given replaces that class only; `a|b`: one of
them is enough):

```yaml
coverage:
  stale_days: 7
  expected:
    Server: [openvas, trivy|dnf-updateinfo]       # defaults shown
    VirtualMachine: [openvas, trivy|dnf-updateinfo]
    Hypervisor: [openvas, trivy|dnf-updateinfo]
    PC: [edr]                                      # no EDR connector yet: a PC stays partial
    default: [openvas]                             # every other class
```

Where to read it: the Grafana dashboard `coverage` (`docs/reporting.md`), `GET …/coverage` of the
decision service, and in the chat "which servers were never scanned?" (`list_coverage`).

## 5. When the connector fails

| Journal | Cause | Remedy |
| --- | --- | --- |
| `iTop not reached` | Address, DNS, firewall, certificate not trusted | `curl` of §2 from the collector; `ca_file` |
| `iTop refused: code 1: … permissions` | The account reads nothing | Profile *Document author* (or another reading one) besides *REST Services User* |
| `iTop refused: code 1: Invalid login` | Wrong user or password | The password file and the account |
| `something else than JSON` | Wrong URL, or a sign-in page in front of the API | The URL of iTop, without `/webservices` |
| `password_file … is empty` | The file is missing or empty | Its path in `collector.yaml` |

## 6. Seeding the CMDB

The hosts scanned but not in the CMDB, from the `triage.json` of a run (download it from the daily
run, or from the decision service), as a CSV for the CSV import of iTop:

```bash
detect cmdb export triage.json --organization Lab --out cmdb-candidates.csv
```

Columns `name`, `org_id->name`, `status`, `managementip`, `business_criticity` (empty: to fill),
`description` (sources, OS, "likely a server" when an account scanned it). Check each line, split
the file per class, then in iTop: Data administration > CSV import, separator `;`, the class,
the columns mapped by their code. Virtual machines are better synchronised from their
hypervisors by a tool of the tenant (an iTop synchro data source), A2VM keeping to reading.
