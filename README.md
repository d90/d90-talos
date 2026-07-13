# d90-talos

GitOps config for a home Kubernetes cluster: [Talos Linux](https://www.talos.dev/) nodes managed via [Flux](https://fluxcd.io/), all state defined in this repo.

## Layout

```
home/
  flux-system/   Flux's own bootstrap manifests (gotk-components, gotk-sync)
  config/        cluster-wide secrets (sops-encrypted)
  charts/        HelmRepository sources
  crds/          vendored CRDs (cert-manager, traefik) applied ahead of the resources that need them
  core/          cluster infra: cert-manager, storage, vGPU/device plugins, namespaces, reloader
  apps/          workloads: media stack, home automation, networking (traefik, metallb, cilium), misc tools
talos/
  patches/       Talos machine config patches (controlplane, etc.)
scripts/
  bootstrap.sh   reference commands for bootstrapping a fresh cluster (not a turnkey script — read before running)
```

`home/kustomization.yaml` is the root Flux points at; everything under `home/` is built with `kustomize build home`.

## Secrets

Secrets are encrypted in place with [SOPS](https://github.com/getsops/sops) + age (`*.sops.yaml`, or plain `.yaml` files with SOPS-encrypted `data`/`stringData` values — e.g. `home/apps/default/configmaps/lsio-defaults.yaml`). Flux's kustomize-controller decrypts them on reconcile using the age key stored as the `sops-age` secret in `flux-system` — see `scripts/bootstrap.sh` for how that secret gets created. Never commit an unencrypted age private key or plaintext secret values.

## Bootstrapping a cluster

`scripts/bootstrap.sh` documents the sequence (apply Talos configs → bootstrap etcd → fetch kubeconfig → create the `sops-age` secret → `flux bootstrap github`), but the actual commands are commented out — treat it as a checklist, not a script to run unattended.

## Dependency updates

[Renovate](https://docs.renovatebot.com/) watches this repo (`renovate.json`) and opens PRs for new image/chart/flux versions. Patch and minor updates automerge once CI passes; major version bumps always stop for manual review (labeled `major-update`). Check the [Dependency Dashboard issue](../../issues) for anything Renovate flagged but hasn't opened a PR for yet.

## CI

`.github/workflows/validate.yml` runs `kustomize build` + `kubeconform` on every PR and push to `main`, to catch manifests that don't parse or don't match their Kubernetes schema before they reach the cluster.
