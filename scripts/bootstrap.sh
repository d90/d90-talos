#!/usr/bin/env bash
# Bootstrap script for Talos + FluxCD
# See MIGRATION_STRATEGY.md Phase 1-2 for full instructions
set -euo pipefail

GITHUB_USER="${GITHUB_USER:-d90}"
GITHUB_REPO="${GITHUB_REPO:-d90-talos}"

echo "==> Applying Talos machine configs..."
# talosctl apply-config --insecure --nodes $NODE1 --file talos/controlplane.yaml
# talosctl apply-config --insecure --nodes $NODE2 --file talos/controlplane.yaml

echo "==> Bootstrapping etcd (run on node 1 only)..."
# talosctl bootstrap --nodes $NODE1

echo "==> Fetching kubeconfig..."
# talosctl kubeconfig --nodes $NODE1 ./kubeconfig
# export KUBECONFIG=./kubeconfig

echo "==> Creating sops-age secret..."
# kubectl create namespace flux-system
# cat ~/.config/sops/age/keys.txt | kubectl create secret generic sops-age \
#   --namespace=flux-system --from-file=age.agekey=/dev/stdin

echo "==> Bootstrapping Flux..."
# flux bootstrap github \
#   --owner=$GITHUB_USER \
#   --repository=$GITHUB_REPO \
#   --branch=main \
#   --path=home/ \
#   --personal

echo "Done. Monitor with: flux get kustomization -A --watch"
