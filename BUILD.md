# Building OpenShell from Source

## Prerequisites

- Fedora 44 toolbox (or equivalent with gcc, protobuf-compiler, z3-devel, clang-devel, openssl-devel, cmake)
- Rust 1.90+ (the workspace `rust-version`)
- Go 1.26+ (for the agent-sandbox controller)

All builds happen inside `toolbox` because the host (Fedora Atomic) doesn't have the build toolchain.

## Building the Binaries

### Gateway, CLI, and KubeVirt Driver

```bash
# Build with bundled z3 (statically links z3, no libz3 runtime dependency)
toolbox run bash -c 'cd /path/to/OpenShell && \
  cargo build --release \
    -p openshell-server \
    -p openshell-cli \
    -p openshell-driver-kubevirt \
    --features bundled-z3'
```

Without `--features bundled-z3`, the binaries link dynamically against `libz3.so.4.16` and require it at runtime. The bundled build takes longer (compiles z3 from source) but produces portable binaries.

### Sandbox Supervisor

```bash
# openshell-sandbox does not use z3
toolbox run bash -c 'cd /path/to/OpenShell && \
  cargo build --release -p openshell-sandbox'
```

### Output

Binaries are in `target/release/`:
- `openshell` (CLI)
- `openshell-gateway` (gateway server)
- `openshell-driver-kubevirt` (KubeVirt compute driver)
- `openshell-sandbox` (sandbox supervisor, runs inside pods/VMs)

## Installing the CLI

```bash
cp target/release/openshell ~/.local/bin/openshell
openshell --version
```

If built without `bundled-z3`, you need a wrapper:
```bash
cat > ~/.local/bin/openshell << 'EOF'
#!/bin/bash
exec toolbox run /path/to/OpenShell/target/release/openshell "$@"
EOF
chmod +x ~/.local/bin/openshell
```

## Building Container Images

### Gateway

```bash
BUILDDIR=$(mktemp -d -p ~)
cp target/release/openshell-gateway "$BUILDDIR/"
cat > "$BUILDDIR/Containerfile" << 'EOF'
FROM registry.fedoraproject.org/fedora-minimal:44
COPY openshell-gateway /usr/local/bin/openshell-gateway
ENTRYPOINT ["/usr/local/bin/openshell-gateway"]
EOF
podman build -f "$BUILDDIR/Containerfile" -t localhost/openshell-gateway:dev "$BUILDDIR"
rm -rf "$BUILDDIR"
```

### KubeVirt Driver

```bash
BUILDDIR=$(mktemp -d -p ~)
cp target/release/openshell-driver-kubevirt "$BUILDDIR/"
cat > "$BUILDDIR/Containerfile" << 'EOF'
FROM registry.fedoraproject.org/fedora-minimal:44
COPY openshell-driver-kubevirt /usr/local/bin/openshell-driver-kubevirt
ENTRYPOINT ["/usr/local/bin/openshell-driver-kubevirt"]
EOF
podman build -f "$BUILDDIR/Containerfile" -t localhost/openshell-driver-kubevirt:dev "$BUILDDIR"
rm -rf "$BUILDDIR"
```

Use `fedora-minimal:44` as the base (matches the toolbox's glibc). The upstream distroless gateway image has an older glibc/libstdc++ that is incompatible with Fedora 44 compiled binaries.

## Deploying to CRC (OpenShift)

### Push images to internal registry

```bash
REGISTRY=default-route-openshift-image-registry.apps-crc.testing
oc login -u kubeadmin https://api.crc.testing:6443 --insecure-skip-tls-verify
podman login --tls-verify=false -u kubeadmin -p "$(oc whoami -t)" "$REGISTRY"

podman tag localhost/openshell-gateway:dev "$REGISTRY/<namespace>/openshell-gateway:dev"
podman push --tls-verify=false "$REGISTRY/<namespace>/openshell-gateway:dev"
```

### Running as Quadlet (local Podman)

The gateway and driver can run as systemd Quadlet units. See `~/.config/containers/systemd/openshell-gateway.container` and `openshell-driver-kubevirt.container`.

The gateway needs:
- TLS certs (mounted from `~/.local/state/openshell/tls/`)
- JWT signing keys (mounted from `~/.local/state/openshell/tls/jwt/`)
- Gateway config (mounted from `~/.config/openshell/gateway.toml`)
- Podman socket (for the Podman driver)
- Shared socket volume (for out-of-process drivers like KubeVirt)

The driver needs:
- Kubeconfig (for K8s API access)
- Shared socket volume (for the gateway to connect via UDS)

## Building the Container Disk Image (KubeVirt)

The container disk image is a qcow2 wrapped in a container image. Built on CRC via an OpenShift BuildConfig using `virt-customize`.

```bash
# Create build resources
oc new-project openshell-sandboxes
oc create imagestream openshell-sandbox-kubevirt -n openshell-sandboxes
oc apply -f buildconfig.yaml  # see agents/hermes/openshell/Dockerfile.kubevirt-minimal

# Build
BUILDDIR=$(mktemp -d)
cp target/release/openshell-sandbox "$BUILDDIR/"
cp Dockerfile.kubevirt-minimal "$BUILDDIR/Dockerfile"
oc start-build openshell-sandbox-kubevirt --from-dir="$BUILDDIR" -n openshell-sandboxes --follow
```

The resulting image is at:
```
image-registry.openshift-image-registry.svc:5000/openshell-sandboxes/openshell-sandbox-kubevirt:latest
```

## Toolbox Build Environment

If `toolbox run` exits with code 144 (signal kill from background jobs), use `podman exec` instead:

```bash
podman exec -u 1000 \
  -e HOME=/var/home/shanemcd \
  -e GOPATH=/var/home/shanemcd/go \
  -e GOMODCACHE=/var/home/shanemcd/go/pkg/mod \
  -e CGO_ENABLED=0 \
  fedora-toolbox-44 \
  bash -c 'cd /path/to/project && go build ./...'
```

For Rust builds, `toolbox run` usually works:
```bash
toolbox run bash -c 'cd /path/to/OpenShell && cargo build --release -p openshell-cli --features bundled-z3'
```
