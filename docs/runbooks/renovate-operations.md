# Runbook: Renovate operations

## Configuration ownership

The self-hosted Renovate configuration in `apps/renovate.yaml` is authoritative.
It explicitly lists the repositories Renovate may modify. Renovate must not
auto-discover every repository visible to the GitHub App.

The global configuration sets:

- `onboarding: false`
- `requireConfig: "ignored"`
- `automerge: false`

These settings let self-hosted Renovate operate on the listed repositories
without creating a repository-level onboarding PR. Every upgrade still has to
pass the required `Render and server-side validate` check before merge.

## Do not close onboarding blindly

Closing an onboarding PR while `requireConfig` still requires a repository
config causes Renovate to mark that repository as disabled on the next run.

Before closing an onboarding PR:

1. Confirm `apps/renovate.yaml` contains `onboarding: false`.
2. Confirm it contains `requireConfig: "ignored"`, or confirm the repository has
   an intentional `renovate.json`.
3. Run Renovate manually and verify the repository log says it was processed,
   not `disabled-closed-onboarding`.

## Manual verification

Create a one-off job from the current CronJob without changing its schedule:

```bash
kubectl -n renovate create job \
  --from=cronjob/renovate \
  "renovate-manual-$(date +%s)"
kubectl -n renovate logs "job/renovate-manual-<timestamp>" --follow
```

A healthy run processes the configured repositories and either reports no
available updates or opens branches for review.
