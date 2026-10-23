# Démo Industrie (fictitious tenant)

A first tenant for a new A2VM installation: real products, invented company, names and
addresses. There is no scanner: the assets of `client.yaml` are matched against the CVE records by
vendor, product and version (`detect inventory`), which is enough to run the whole chain
(intelligence, detection, triage, reporting, watch) before any scanner is connected.

| File | Role |
| --- | --- |
| `.gitlab-ci.yml` | Includes the A2VM pipeline at a fixed version: replace `group/subgroup/a2vm` |
| `client.yaml` | Nine declared assets with exposure, criticality, zone and owner (one OT asset with a material well-being impact); a watchlist of ten products |
| `contacts.yaml` | Who receives the alerts, by level |

Copy these files into an empty tenant project, then follow `docs/deployment.md`, section 5.
The first daily run can be started by hand with `TRIAGE_SINCE=30d` to get a month of CVEs.
