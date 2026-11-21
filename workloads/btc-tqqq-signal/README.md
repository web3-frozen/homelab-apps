# BTC/TQQQ signal CronJob

The CronJob runs daily at 08:20 Hong Kong time (Asia/Hong_Kong) and emits
signals to the Job log. Argo CD deploys the private GHCR image pinned by digest
in kustomization.yaml.

The ExternalSecret uses the cluster's Infisical store to sync
BTC_TQQQ_GHCR_READ_TOKEN from the homelab project's prod environment at / into
ghcr-pull-secret. The Infisical credential is a classic GitHub PAT with
read:packages. Verify the ExternalSecret is Ready and the cluster can pull the
pinned digest before enabling the workload.

Verified builds on master in web3-frozen/btc-tqqq-signal submit image digest
updates as GitOps pull requests. GitHub merges the update after its checks
pass and Argo CD applies the new digest.

After Argo CD syncs the Application, verify signal output with a one-off Job.

```bash
kubectl -n btc-tqqq-signal create job --from=cronjob/btc-tqqq-signal btc-tqqq-signal-smoke
kubectl -n btc-tqqq-signal wait --for=condition=complete job/btc-tqqq-signal-smoke --timeout=600s
kubectl -n btc-tqqq-signal logs job/btc-tqqq-signal-smoke -c signals
```
