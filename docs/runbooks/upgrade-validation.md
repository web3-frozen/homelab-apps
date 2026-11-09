# Runbook: Automated upgrade validation

## Required gate

The `Validate GitOps upgrades` GitHub Actions workflow is the required
pre-merge gate for Applications, platform manifests, workloads, and dependency
updates.

It performs five checks:

1. Parse every Kubernetes YAML document in `apps/`, `platform/`, and
   `workloads/`.
2. Render every Helm Application with its exact chart version and
   `valuesObject`.
3. Render every Kustomization with `kubectl kustomize`.
4. Create an ephemeral kind cluster, install bootstrap and workload CRDs, then
   run `kubectl apply --dry-run=server` for every rendered candidate.
5. Resolve every non-private container image tag with
   `go-containerregistry/crane`, so a nonexistent image fails before merge.

The workflow must be configured as a required status check for `main`. A failed
render, policy/schema error, invalid CRD, or server-side rejection blocks merge.

## Upgrade flow

1. Renovate or an operator opens a pull request.
2. `Validate GitOps upgrades` renders the complete candidate set.
3. Review the diff and upgrade-specific notes.
4. Merge only after the required check passes.
5. ArgoCD syncs the new versions from `main`.

Never force-merge a failed upgrade PR. Fix the manifest or keep the old version.

## Limits

Server-side dry-run proves that the candidate is renderable and accepted by the
Kubernetes API. It does not prove that a controller behaves correctly at
runtime.

- Singleton platform upgrades such as Longhorn, ArgoCD, cert-manager, ESO,
  Kyverno, and monitoring require an additional staging-cluster rehearsal for
  major or high-risk changes.
- Workload traffic promotion belongs in Argo Rollouts analysis, not the
  pre-merge render gate.
- Probe timing cannot be proven by schema validation. After a workload rollout,
  inspect container restart counts and probe failures even when the Argo
  Application reports `Synced / Healthy`. Use a startup probe for slow
  initialization, and keep liveness thresholds separate from readiness
  thresholds so a temporary dependency delay does not cause a restart loop.
- Database migrations need a restore-tested backup and a rollback plan even
  when the dry-run passes.

## Local preflight

```bash
python3 scripts/validate_gitops.py --output .validation-renders
```

The script requires Helm, kubectl, and PyYAML. It intentionally rejects a
floating Helm chart version; chart Applications must use an explicit
`targetRevision`.

The kind/server-side phase runs in GitHub Actions because it needs a disposable
Kubernetes control plane.
