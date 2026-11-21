# BTC/TQQQ signal and broker CronJobs

The signal CronJob runs daily at 08:20 Hong Kong time (Asia/Hong_Kong) and
emits signals to the Job log. Argo CD deploys the private GHCR image pinned by
digest in kustomization.yaml.

The broker CronJobs run from the same image and share a small Longhorn volume
for SQLite ledgers and the Webull token cache:

- `btc-tqqq-binance` runs on Monday at 00:20 UTC. It is in `test` mode, so the
  calculated order is validated without being placed.
- `btc-tqqq-webull` runs before each US regular-session open. The model skips
  days that are not its weekly execution window. It stays `disabled` until the
  Webull credentials exist in Infisical.

`BINANCE_MAX_*` and `WEBULL_MAX_*` in `broker-config.yaml` are safety ceilings,
not target allocations. Review them before enabling live trading.

The ExternalSecret uses the cluster's Infisical store to sync
BTC_TQQQ_GHCR_READ_TOKEN from the homelab project's prod environment at / into
ghcr-pull-secret. The Infisical credential is a classic GitHub PAT with
read:packages. Verify the ExternalSecret is Ready and the cluster can pull the
pinned digest before enabling the workload.

Binance credentials come from `BTC_TQQQ_BINANCE_API_KEY` and
`BTC_TQQQ_BINANCE_API_SECRET`. Telegram delivery uses the shared
`INFRA_TELEGRAM_BOT_TOKEN` and `INFRA_TELEGRAM_BOT_CHAT_ID` entries. The Webull
secret is optional so the disabled job can run; add these Infisical keys and an
ExternalSecret before changing `WEBULL_EXECUTION_MODE`:

- `BTC_TQQQ_WEBULL_APP_KEY`
- `BTC_TQQQ_WEBULL_APP_SECRET`
- `BTC_TQQQ_WEBULL_ACCOUNT_ID`

Verified builds on master in web3-frozen/btc-tqqq-signal submit image digest
updates as GitOps pull requests. GitHub merges the update after its checks
pass and Argo CD applies the new digest.

After Argo CD syncs the Application, verify signal output with a one-off Job.

```bash
kubectl -n btc-tqqq-signal create job --from=cronjob/btc-tqqq-signal btc-tqqq-signal-smoke
kubectl -n btc-tqqq-signal wait --for=condition=complete job/btc-tqqq-signal-smoke --timeout=600s
kubectl -n btc-tqqq-signal logs job/btc-tqqq-signal-smoke -c signals
```

Check Binance connectivity without creating an order:

```bash
kubectl -n btc-tqqq-signal create job --from=cronjob/btc-tqqq-binance \
  btc-tqqq-binance-probe --dry-run=client -o json \
  | jq '.spec.template.spec.containers[0].command = ["python", "-B", "-u", "/app/trade.py", "--brokers", "binance", "--probe", "--state-dir", "/var/lib/btc-tqqq"]' \
  | kubectl apply -f -
```
