# Deployment on GitLab (multi-tenant)

```
vulnops/                 group — group runner, shared CI/CD variables (LLM endpoint)
├── a2vm                  code project — no client data; releases are tags vX.Y.Z
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
| `A2VM_LLM_ENABLED` | `true` | Visible, not protected |
| `A2VM_LLM_BASE_URL` | `http://192.0.2.103:8000/v1`; several endpoints of the same model, comma-separated (v0.15.0, `docs/chat.md` §5) | Visible, not protected |
| `A2VM_LLM_MODEL` | `qwen3-14b` | Visible, not protected |
| `LLM_API_KEY` | (only if the server requires one) | Masked, protected |

In another GitLab layout (the code project elsewhere than `vulnops/a2vm`, runners with other tags),
set on the same group:

| Key | Example | Options |
| --- | --- | --- |
| `A2VM_PROJECT` | `<group>/<subgroup>/a2vm`: the path of the code project | Visible |
| `A2VM_RUNNER_TAG`, `A2VM_COLLECT_TAG` | the tag of the runner that reaches the LLM and the targets | Visible |

A group variable takes precedence over the defaults of the pipeline template; the `include:
project:` of each client `.gitlab-ci.yml` names the same path (`examples/demo-industrie`).

A client project can override any of them (e.g. another engine for a client that allows cloud).
Optional Google Threat Intelligence enrichment: `A2VM_GTI_ENABLED` and `GTI_API_KEY` (masked,
protected), see `docs/gti.md`.

## 4. Code project `vulnops/a2vm`

1. Create the project in the group `vulnops`, **without** a README (empty repository).
2. Push the code and the release tag:

```bash
git clone a2vm.bundle a2vm && cd a2vm
git remote set-url origin git@gitlab.lab.example:vulnops/a2vm.git
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
  - project: vulnops/a2vm
    ref: v0.17.0
    file: templates/client-pipeline.yml
variables:
  A2VM_REF: v0.17.0
  A2VM_RUN_MODE: gitlab   # or kubernetes: docs/kubernetes.md §4
```

3. If `targets.yaml` is used: scan key and target accounts as in `docs/scanning.md`, then the
   variable `A2VM_SSH_KEY` (File, protected) in this project.
4. **Build > Pipeline schedules > New schedule**: daily (e.g. `45 5 * * *`, Europe/Paris), branch
   `main`. Optional variables: `TRIAGE_SINCE` (default `26h`).
5. First run: **Build > Pipelines > Run pipeline** on `main` (optional `TRIAGE_CVES`).

The push pipeline runs `validate` only (profile schema, targets file, client id, and since
v0.11.3 the include `ref:` against `A2VM_REF`: two different versions fail the job). Schedules and
manual runs run `collect` → `intel` → `detect` → `assets` → `triage`; the report, the asset
inventory and the reporting dataset (`output/<client>/reporting.json`) are in the `triage` job
artifacts (30 days); with the reporting variables below, the `publish` job then loads the dataset
into the reporting database (`docs/reporting.md`). The first line of every job names the A2VM version and the mode (`daily` or
`watch`).

Optional client project variables:

| Key | Use | Options |
| --- | --- | --- |
| `A2VM_EXTERNAL_PROJECT` | External collection project to join (`docs/openvas.md`, section 6) | Visible |
| `A2VM_GITLAB_TOKEN` | Project access token of the external project (Reporter, `read_api`), required on GitLab CE | Masked, protected |
| `A2VM_ANALYST_TO` | Analysts who validate the alerts (`docs/alerts.md`) | Visible |
| `A2VM_SOURCE_FAILURES` | Failed runs in a row before a watch source is an error (default 3) | Visible |
| `A2VM_REPORTING_DSN` | Reporting database, writer role: `postgresql://a2vm_writer:…@host/a2vm` (`docs/reporting.md`) | Masked and hidden, protected |
| `A2VM_REPORTING_CA` | Certificate of the reporting database | File, protected |
| `A2VM_SEND_ONLY`, `A2VM_TEST_TO` | Set in the form of the manual jobs `send-alerts` and `test-mail`, not as project variables | — |

### On Kubernetes (since v0.12.0)

With the variable `A2VM_K8S_CONTEXT`, a push to the default branch also deploys the tenant's daily
run as a Kubernetes CronJob (job `deploy-k8s`): prerequisites, variables and checks in
`docs/kubernetes.md`.
With a `collectors.yaml` (since v0.13.0), it also deploys the tenant's detection service, where
collectors near the client networks push their detections (`docs/collectors.md`).

## 6. Releasing a new version

1. Bump `version` in the four package `pyproject.toml` (`a2vm`, `via`, `detect`, `verdict`), the
   `__version__` of `a2vm` and `via` and the chart's `Chart.yaml`, merge, tag `vX.Y.Z` on `main`,
   push the tag: the `release` job checks that the tag, the package and the chart versions agree;
   the `images` job then builds the pillar images (when the instance has a registry).
2. In each client project, change `ref` and `A2VM_REF` in `.gitlab-ci.yml`, one client at a
   time if needed.

## 7. Publishing the documentation to a product project

The job `sync-product-docs` of the code project copies `docs/` into another project where the
teams read the reference (for example a `product` project holding the documents of every pillar),
on every version tag, or by hand (Run pipeline). The copy is one way and replaces what is there:
edit the source in the code project, never the copy.

1. In the product project: **Settings > Access tokens**, a project access token, role Maintainer
   (or Developer if developers may push to the default branch), scope `write_repository`, with an
   expiry date.
2. In the code project, **Settings > CI/CD > Variables**:

   | Key | Value | Options |
   | --- | --- | --- |
   | `PRODUCT_DOCS_REPO` | path of the product project | Visible |
   | `PRODUCT_DOCS_PATH` | folder of the copy, e.g. `docs` or `docs/a2vm` | Visible |
   | `PRODUCT_SYNC_TOKEN` | the token | Masked and hidden, protected |

3. Push a tag: the job pushes one commit "docs: sync from … vX.Y.Z" to the product project, and
   writes `.synced-from` (source and version) in the folder.

`PRODUCT_DOCS_PATH` is copied with deletion: a file that exists only there is removed. Give A2VM
its own folder when other teams write next to it. Without the three variables the job does not run.

## CI/CD variables renamed in v0.11.1

The CI/CD variables are named `A2VM_*` since v0.11.1 (formerly `VULNOPS_*`). Until a later version,
a job still reads a `VULNOPS_<name>` whose `A2VM_<name>` is not defined, and logs
`WARN  CI/CD variable VULNOPS_<name> is deprecated: rename it A2VM_<name>`. Rename each variable in
Settings > CI/CD > Variables (group, subgroup, client projects), in the `variables:` section of each
client `.gitlab-ci.yml`, in the pipeline schedules (`A2VM_JOB=watch`) and in the environment of a
runner outside the LAN (`A2VM_SERVER_URL`). Exception: the variables the template itself defines
(`A2VM_REF`, `A2VM_PROJECT`, `A2VM_PROFILE`, `A2VM_TARGETS`, `A2VM_RUNNER_TAG`, `A2VM_COLLECT_TAG`)
are not copied from their old names: rename them in the client `.gitlab-ci.yml` at the same time as
the move to v0.11.1. A job without warnings has nothing left to rename.
