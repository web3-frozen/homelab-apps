# Runbook: Monitoring Helm Ownership Migration

> **Historical procedure - completed 2026-11-08.** The monitoring and Beyla
> charts are already ArgoCD-managed and no longer exist in Pulumi state. Do not
> rerun these state-delete commands. For any future ownership migration, use
> the dependency-safe procedure in
> `pulumi-k3s-proxmox/docs/runbooks/helm-ownership-migration-2026-11-09.md`.

## Context

kube-prometheus-stack and Beyla were originally created by the Pulumi program.
They are now declared as Argo CD Applications:

- `monitoring` uses `apps/monitoring.yaml`
- `beyla` uses `apps/beyla.yaml`

Argo CD adopts the existing Kubernetes resources by Server-Side Apply. The
state-delete commands below are retained as a historical record, not as a
current runbook.

## Safe Migration Order

1. Back up Pulumi state:

   ```bash
   PULUMI_CONFIG_PASSPHRASE="" pulumi stack export --file homelab-before-monitoring-migration.json
   ```

2. Confirm Argo CD owns both releases:

   ```bash
   kubectl -n argocd get applications monitoring beyla
   ```

3. Confirm both Applications are `Synced` and `Healthy`.

4. Remove the old Pulumi chart entries from state only. This does not delete
   cluster resources:

   ```bash
   pulumi state delete --force \
     'urn:pulumi:homelab::pulumi-k3s-proxmox::kubernetes:helm.sh/v4:Chart::kube-prometheus-stack'
   pulumi state delete --force \
     'urn:pulumi:homelab::pulumi-k3s-proxmox::kubernetes:helm.sh/v4:Chart::beyla'
   ```

5. Remove the obsolete Pulumi-created Beyla dashboard from state:

   ```bash
   pulumi state delete --force \
     'urn:pulumi:homelab::pulumi-k3s-proxmox::kubernetes:core/v1:ConfigMap::beyla-grafana-dashboard'
   ```

6. Update the Pulumi program so it no longer declares the monitoring and Beyla
   Helm charts or the Beyla dashboard.

7. Run `pulumi preview` and verify there are no destroy steps for monitoring or
   Beyla resources.

## Failure Recovery

If Argo CD does not adopt a resource, do not delete the resource first. Inspect:

```bash
kubectl -n argocd get application monitoring -o yaml
kubectl -n argocd get application beyla -o yaml
```

Common causes are immutable fields, conflicting field managers, or a missing
`grafana-admin` Secret. Resolve those first, then sync again.

If Pulumi state must be restored, use the state export from step 1.
