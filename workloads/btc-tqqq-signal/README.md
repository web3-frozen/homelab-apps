# BTC/TQQQ signal CronJob

Argo CD syncs the public deployment manifests. The init container fetches the
signal implementation and history from a pinned private repository commit into
an in-memory volume. The main container receives the source as a read-only mount.

The job runs daily at 00:20 UTC (08:20 Hong Kong) and emits the strategy signals
to Job logs. This initial Application deploys the signal monitor.

## Infisical identity

Provision a read-only Infisical Kubernetes Auth machine identity for the
`btc-tqqq-source-loader` ServiceAccount in namespace `btc-tqqq-signal`.
Bind the token audience to `infisical` and grant it read access to
`GITHUB_WEB3_FROZEN_READ_TOKEN` in `homelab / prod / /`.
Keep the credential values in Infisical. Set the identity and project UUIDs
in the following ConfigMap on the target cluster before enabling the schedule.

```bash
kubectl -n btc-tqqq-signal create configmap btc-tqqq-source-identity \
  --from-literal=INFISICAL_IDENTITY_ID='REPLACE_WITH_IDENTITY_ID' \
  --from-literal=INFISICAL_PROJECT_ID='REPLACE_WITH_PROJECT_ID' \
  --dry-run=client -o yaml | kubectl apply -f -
```

After Argo CD syncs the Application, verify the source pull and signal output
with a one-off Job.

```bash
kubectl -n btc-tqqq-signal create job --from=cronjob/btc-tqqq-signal btc-tqqq-signal-smoke
kubectl -n btc-tqqq-signal wait --for=condition=complete job/btc-tqqq-signal-smoke --timeout=600s
kubectl -n btc-tqqq-signal logs job/btc-tqqq-signal-smoke -c signals
```

The public Python runtime is pinned by digest. The application source revision
is pinned in `fetch_source.py`.
