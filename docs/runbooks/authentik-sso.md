# Runbook: Authentik and OIDC

## Access

- URL: `https://auth.<domain>`
- Bootstrap username: `akadmin`
- Bootstrap password: Infisical `homelab / prod / /`,
  key `INFRA_AUTHENTIK_BOOTSTRAP_PASSWORD`

The host is restricted by `authentik-ip-allowlist` in
`platform/authentik/ingress.yaml`. Update its `/32` when the administrator
public IP changes. Do not expose the Authentik host outside that allowlist.

ArgoCD has a separate allowlist managed by Pulumi. Its local `admin` account is
the break-glass path if Authentik is unavailable.

## Applications

| Application | OIDC client ID | Callback |
|---|---|---|
| `authentik-config` | n/a | Provisions PostgreSQL, secrets, blueprints, and ingress |
| `authentik` | n/a | GoAuthentik Helm chart |
| ArgoCD | `argocd` | `https://argocd.<domain>/auth/callback` |
| Grafana | `grafana` | `https://grafana.<domain>/login/generic_oauth` |

The `homelab-sso` blueprint creates both providers and applications.
`homelab-admins` maps to ArgoCD `role:admin` and Grafana `Admin`.

## Secrets

All runtime secrets are delivered by External Secrets Operator:

- `INFRA_AUTHENTIK_SECRET_KEY`
- `INFRA_AUTHENTIK_DB_PASSWORD`
- `INFRA_AUTHENTIK_BOOTSTRAP_PASSWORD`
- `INFRA_AUTHENTIK_BOOTSTRAP_TOKEN`
- `INFRA_AUTHENTIK_ARGOCD_CLIENT_SECRET`
- `INFRA_AUTHENTIK_GRAFANA_CLIENT_SECRET`

Never print these values in logs, tickets, or agent output.

## Operational notes

- The first startup runs a full schema migration. It can take several minutes,
  consume the 500m CPU limit, and return HTTP 500 from health probes while the
  migration continues. Check log progress before restarting.
- Do not use `ak shell` against the live server. It previously exceeded the
  1 GiB limit and restarted the pod. The limit is now 1536 MiB; use REST API or
  a temporary resource-limited Job for diagnostics.
- CloudNativePG can host multiple databases, but Authentik intentionally has a
  separate PostgreSQL cluster to keep SSO out of an application database's
  failure domain.
- Grafana must keep `server.root_url` set to its public HTTPS URL. Without it,
  Grafana generates a `localhost:3000` callback that Authentik rejects.
- Grafana sidecars preserve the `Homelab` folder, so the home dashboard path
  must be `/tmp/dashboards/Homelab/homelab-overview.json`, not the old path
  without the folder segment.

## Verification

```bash
kubectl -n argocd get applications authentik authentik-config monitoring
kubectl -n authentik get cluster,pods,externalsecret
kubectl -n authentik get middleware authentik-ip-allowlist
curl -I https://auth.<domain>
curl -I https://argocd.<domain>/auth/login
curl -I https://grafana.<domain>/login/generic_oauth
```

OIDC discovery:

```bash
curl -fsS https://auth.<domain>/application/o/argocd/.well-known/openid-configuration
```

The ArgoCD flow must use PKCE and request the `groups` ID-token claim.
