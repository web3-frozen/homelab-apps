#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

render_dir=${1:?Pass the directory containing rendered GitOps manifests}
tmp_dir=$(mktemp -d)
cleanup() {
  for pid in "${api_pid:-}" "${etcd_pid:-}"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
  if [[ ${1:-0} != 0 ]]; then
    tail -n 40 "$tmp_dir"/*.log >&2 || true
  fi
  rm -rf -- "$tmp_dir"
}
trap 'cleanup $?' EXIT

# Use a fresh local Kubernetes API and etcd in the job, with no access to the live cluster.
version=v1.37.0
archive=envtest-$version-linux-amd64.tar.gz
curl -fsSL --retry 3 \
  "https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-$version/$archive" \
  -o "$tmp_dir/$archive"
printf '%s  %s\n' f03faedfc68d2a78cee5cb02618bb44e7f67044f4c5fc957f72d3307fda61a9c "$tmp_dir/$archive" \
  | sha256sum --check
tar -xzf "$tmp_dir/$archive" -C "$tmp_dir"
bin="$tmp_dir/controller-tools/envtest"

"$bin/etcd" --data-dir="$tmp_dir/etcd" \
  --listen-client-urls=http://127.0.0.1:2379 --advertise-client-urls=http://127.0.0.1:2379 \
  --listen-peer-urls=http://127.0.0.1:2380 --initial-advertise-peer-urls=http://127.0.0.1:2380 \
  --initial-cluster=default=http://127.0.0.1:2380 \
  >"$tmp_dir/etcd.log" 2>&1 &
etcd_pid=$!

openssl req -new -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=IP:127.0.0.1' \
  -keyout "$tmp_dir/tls.key" -out "$tmp_dir/tls.crt" 2>"$tmp_dir/openssl.log"
token=$(openssl rand -hex 32)
printf '%s,ci,ci,system:masters\n' "$token" > "$tmp_dir/token.csv"
"$bin/kube-apiserver" --bind-address=127.0.0.1 --advertise-address=127.0.0.1 --secure-port=6443 \
  --endpoint-reconciler-type=none \
  --allow-privileged=true \
  --etcd-servers=http://127.0.0.1:2379 --service-cluster-ip-range=10.250.0.0/24 \
  --tls-cert-file="$tmp_dir/tls.crt" --tls-private-key-file="$tmp_dir/tls.key" \
  --token-auth-file="$tmp_dir/token.csv" --authorization-mode=RBAC \
  --service-account-issuer=https://127.0.0.1:6443 --service-account-key-file="$tmp_dir/tls.key" \
  --service-account-signing-key-file="$tmp_dir/tls.key" >"$tmp_dir/apiserver.log" 2>&1 &
api_pid=$!

export KUBECONFIG="$tmp_dir/kubeconfig"
ctl="$bin/kubectl"
"$ctl" config set-cluster validation --server=https://127.0.0.1:6443 --certificate-authority="$tmp_dir/tls.crt"
"$ctl" config set-credentials ci --token="$token"
"$ctl" config set-context validation --cluster=validation --user=ci
"$ctl" config use-context validation
for ((attempt = 0; attempt < 60; attempt++)); do
  if "$ctl" --request-timeout=2s get --raw=/readyz >/dev/null 2>&1; then break; fi
  kill -0 "$api_pid"
  sleep 1
done
"$ctl" --request-timeout=5s get --raw=/readyz >/dev/null

"$ctl" apply --server-side --field-manager=gitops-validation -f "$render_dir/crds.yaml"
"$ctl" wait --for=condition=Established crd --all --timeout=180s
"$ctl" apply -f "$render_dir/namespaces.yaml"
for manifest in "$render_dir"/applications.yaml "$render_dir"/chart-*.yaml "$render_dir"/kustomize-*.yaml "$render_dir"/raw-manifests.yaml; do
  printf 'Validating %s\n' "$manifest"
  "$ctl" apply --server-side --field-manager=gitops-validation --force-conflicts \
    --dry-run=server -f "$manifest" >/dev/null
done
