# CloudNativePG operator (once per Kubernetes cluster)

The tenant's PostgreSQL (v0.18.0, `docs/kubernetes.md` §5) is a `Cluster` of the CloudNativePG
operator, made by the chart in the tenant's namespace. The operator is installed once per
Kubernetes cluster, by an administrator of the cluster, outside the chart (it owns cluster-wide
resources: its CRDs, its webhooks, its namespace `cnpg-system`).

## Install

```bash
kubectl apply --server-side -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.29/releases/cnpg-1.29.3.yaml
kubectl rollout status deployment -n cnpg-system cnpg-controller-manager
kubectl api-resources --api-group=postgresql.cnpg.io
```

The last command lists `clusters`, `backups`, `scheduledbackups`…: `deploy-k8s` looks for this API
group before it enables a tenant's database. Take the latest patch of a supported minor version
(https://cloudnative-pg.io, *Releases*); upgrading the operator is the same command with the new
manifest, the clusters keep running.

## What the operator needs

- The namespace `cnpg-system` must have the label `kubernetes.io/metadata.name: cnpg-system`
  (set by Kubernetes): the tenant's NetworkPolicy lets it reach the instances on 5432 and 8000.
- A default StorageClass, or `A2VM_DATABASE_STORAGE_CLASS` on the tenant project.
- The GitLab agent's access of the tenant projects must allow `postgresql.cnpg.io` `clusters` in
  their namespaces (the chart creates one).

## Backups

The chart sets no backup in v0.18.0. With an object store (S3-compatible), add to the tenant's
cluster a `ScheduledBackup` and its `barmanObjectStore` or the Barman Cloud plugin, as the
operator's documentation describes (*Backup and recovery*). Without one, the data of the services
can be rebuilt: the next daily run, watch passage and pushes of the collectors fill them again;
what is lost is the history of the findings and the journal of the alerts.
