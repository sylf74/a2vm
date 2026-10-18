# Deployment on GitLab (multi-tenant)

```
vulnops/                 group — group runner, shared CI/CD variables (LLM endpoint)
├── vulnops              code project — no client data; releases are tags vX.Y.Z
└── clients/             subgroup — one private project per client
    ├── homelab
    └── <client>
```

Isolation: a client project holds that client's profile, targets, scan key, schedule, pipelines
and reports. Access is granted per client project (or per subgroup); nothing is shared between
clients except the code and the runner.

Host names below are examples; replace `gitlab.lab.example` with the GitLab address.

## 1. Groups

1. **Groups > New group**: `vulnops`, visibility **Private**.
2. In `vulnops`: **New subgroup**: `clients`, **Private**.

## 2. Group runner (once)

1. Group `vulnops` > **Build > Runners > New group runner**: tag `llm-lan`, "Run untagged jobs"
   unchecked. Copy the `glrt-...` token shown.
2. On the runner VM, remove the runners of deleted projects, then register the group runner:

```bash
sudo gitlab-runner verify --delete          # drops runners the server no longer knows
sudo gitlab-runner register --non-interactive \
  --url http://gitlab.lab.example --token glrt-XXXXXXXX \
  --executor docker --docker-image python:3.12-slim --description vulnops-runner
sudo gitlab-runner list
```

The runner then serves every project of the group, including future client projects.

Artifacts: a client with thousands of findings produces exchange files of tens of MB. GitLab's
default limit is 100 MB per artifact (**Admin > Settings > CI/CD > Continuous Integration and
Deployment > Maximum artifacts size**); raw scanner outputs are not kept (hundreds of MB): the
detection files in `work/detect` carry what the later stages use.

## 3. Shared variables (group `vulnops` > Settings > CI/CD > Variables)

| Key | Example | Options |
| --- | --- | --- |
| `VULNOPS_LLM_ENABLED` | `true` | Visible, not protected |
| `VULNOPS_LLM_BASE_URL` | `http://192.0.2.103:8000/v1` | Visible, not protected |
| `VULNOPS_LLM_MODEL` | `qwen3-14b` | Visible, not protected |
| `LLM_API_KEY` | (only if the server requires one) | Masked, protected |

A client project can override any of them (e.g. another engine for a client that allows cloud).
Optional Google Threat Intelligence enrichment: `VULNOPS_GTI_ENABLED` and `GTI_API_KEY` (masked,
protected), see `docs/gti.md`.

## 4. Code project `vulnops/vulnops`

1. Create the project in the group `vulnops`, **without** a README (empty repository).
2. Push the code and the release tag:

```bash
git clone vulnops.bundle vulnops && cd vulnops
git remote set-url origin git@gitlab.lab.example:vulnops/vulnops.git
git push -u origin main && git push origin --tags
```

3. **Settings > Repository > Protected tags**: protect `v*` (Maintainers only): a release tag
   cannot be moved under the client projects' feet.
4. **Settings > CI/CD > Job token permissions**: keep "Limit access to this project" on and **add
   the group `vulnops/clients`**: client pipelines may then clone the code with their job token.

The code project's own pipeline only runs lint, tests and the offline examples.

## 5. A client project (`vulnops/clients/<client>`)

1. Create the project in `vulnops/clients`, private, without a README.
2. Push its content (`client.yaml`, `targets.yaml`, `.gitlab-ci.yml`, `README.md`; start from
   `examples/lab/` of the code project). The `.gitlab-ci.yml` includes the template at a tag:

```yaml
include:
  - project: vulnops/vulnops
    ref: v0.8.6
    file: templates/client-pipeline.yml
variables:
  VULNOPS_REF: v0.8.6
```

3. If `targets.yaml` is used: scan key and target accounts as in `docs/scanning.md`, then the
   variable `VULNOPS_SSH_KEY` (File, protected) in this project.
4. **Build > Pipeline schedules > New schedule**: daily (e.g. `45 5 * * *`, Europe/Paris), branch
   `main`. Optional variables: `TRIAGE_SINCE` (default `26h`).
5. First run: **Build > Pipelines > Run pipeline** on `main` (optional `TRIAGE_CVES`).

The push pipeline runs `validate` only (profile schema, targets file, client id). Schedules and
manual runs run `collect` → `intel` → `detect` → `assets` → `triage`; the report and the asset
inventory are in the `triage` job artifacts (30 days).

## 6. Releasing a new version

1. Bump `version` in the six `pyproject.toml`, merge, tag `vX.Y.Z` on `main`, push the tag: the
   `release` job checks that the tag and the package versions agree.
2. In each client project, change `ref` and `VULNOPS_REF` in `.gitlab-ci.yml`, one client at a
   time if needed.
