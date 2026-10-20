# Client project template (example: a fictitious lab)

Copy this directory into a new project of the `vulnops/clients` group, then replace the example
data with the client's own:

| File | Content |
| --- | --- |
| `client.yaml` | client profile (schema v2): rules, declared assets, defaults |
| `targets.yaml` | read-only SSH collection targets (optional) |
| `settings.yaml` | optional override of the default settings (e.g. LLM routing for this client) |
| `.gitlab-ci.yml` | includes `templates/client-pipeline.yml` of the A2VM code project (`vulnops/a2vm`) at a fixed version |

Project CI/CD variables: `A2VM_SSH_KEY` (File, protected) when `targets.yaml` is used.
Pipeline schedule: daily, on the default branch. See `docs/deployment.md` of the code project.

Host names and addresses in this example are fictitious (`lab.example`, RFC 5737 ranges).
