# Talos Cluster Migration

## Context

This repo (`d90-talos`) is a new Talos-based homelab cluster replacing the old k3s cluster (`homelab-k3s`). Apps are being migrated one at a time. Both clusters run simultaneously during migration, so networking is intentionally separated.

## Cluster State

- Talos nodes: **provisioned and running**
- SOPS age key: **pre-loaded on the cluster** as a Kubernetes secret
- FluxCD: **NOT yet bootstrapped** — this is the next required step before any apps can sync

## Networking

| Cluster | MetalLB Pool |
|---|---|
| homelab-k3s (old) | `10.10.100.80 – 10.10.100.90` |
| d90-talos (new) | `10.10.100.101 – 10.10.100.109` |

Pools are intentionally non-overlapping to avoid L2 ARP conflicts while both clusters are live. `10.10.100.100` is the kube-vip VIP on the old k3s cluster, so the Talos MetalLB pool starts at `.101`. Note: Talos does not use kube-vip — its control plane VIP is handled natively in the Talos machine config.

## Bootstrap Flux (must do first)

Flux manifests are already committed to the repo at `home/flux-system/`. The cluster just needs Flux applied to it.

### Steps

1. Ensure kubeconfig is pointing at the Talos cluster
2. Apply Flux components:
   ```
   kubectl apply -f home/flux-system/gotk-components.yaml
   ```
3. Create the GitHub SSH deploy key secret (if not already present):
   ```
   flux create secret git flux-system \
     --url=ssh://git@github.com/d90/d90-talos.git \
     --namespace=flux-system
   ```
   Add the generated public key as a deploy key in the GitHub repo settings.
4. Apply the sync config:
   ```
   kubectl apply -f home/flux-system/gotk-sync.yaml
   ```
5. Verify Flux is reconciling:
   ```
   flux get kustomizations
   flux get sources git
   ```

## App Migration Order

Migrating one app at a time. Each app needs:
- App manifests in `home/apps/default/<app>/`
- Traefik IngressRoute in `home/apps/networking/traefik/routers/default/<app>.yaml`
- App added to `home/apps/default/kustomization.yaml`

### Status

| App | Manifests in repo | Live on Talos |
|---|---|---|
| bazarr | partial (IngressRoute only) | No |
| cloudnative-pg | yes | No |
| deluge | yes | No |
| dynamic-dns | yes | No |
| homeassistant | yes | No |
| homepage-dashboard | yes | No |
| jellyfin | yes | No |
| lidarr | yes | No |
| mosquitto | yes | No |
| netbootxyz | yes | No |
| nzbget | yes | No |
| profilarr | yes | No |
| prowlarr | yes | No |
| radarr | yes | No |
| scrypted | yes | No |
| seerr | yes | No |
| sonarr | yes | No |
| tasmo | yes | No |
| una | yes | No |
| watchstate | yes | No |
| webnettools | yes | No |

## Next Steps

1. Bootstrap Flux (see above)
2. Complete Bazarr manifests (currently only has IngressRoute — needs workload, service, TLS)
3. Verify Bazarr syncs and is reachable at `https://bazarr.d90.name`
4. Continue migrating remaining apps
