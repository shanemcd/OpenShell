# KubeVirt Compute Driver for OpenShell

A standalone `ComputeDriver` gRPC subprocess that provisions OpenShell sandboxes as KubeVirt `VirtualMachine` resources on OpenShift / Kubernetes clusters with [KubeVirt](https://kubevirt.io) (or OpenShift Virtualization / CNV) installed.

## Architecture

```
openshell-gateway ──UDS──▶ openshell-driver-kubevirt ──K8s API──▶ KubeVirt
       │                           │
       │                           ├─ Creates Secret (cloud-init userdata)
       │                           ├─ Creates VirtualMachine (containerDisk + secretRef)
       │                           └─ Watches VirtualMachineInstance status
       │
       └─ Public gRPC API (CreateSandbox, GetSandbox, ListSandboxes, DeleteSandbox, ...)
```

The driver implements the `ComputeDriver` gRPC service defined in `proto/compute_driver.proto`. The gateway connects to it via a Unix domain socket and delegates sandbox lifecycle operations.

## Prerequisites

- **Cluster**: OpenShift 4.x or Kubernetes with KubeVirt installed
- **CNV / KubeVirt**: Tested on OCP Virt 4.22.0 / KubeVirt 1.x
- **Container disk image**: A qcow2-based `containerDisk` image with:
  - `cloud-init` package installed
  - `openshell-sandbox` binary at `/opt/openshell/bin/openshell-sandbox`
  - `sandbox` user (UID 10001, GID 10001)
  - `sshd` enabled
  - See [Building the Container Disk Image](#building-the-container-disk-image) below
- **Namespace**: The target namespace must exist and the driver's kubeconfig must have permissions to create/delete `VirtualMachine`, `VirtualMachineInstance`, and `Secret` resources

## Quick Start

### 1. Build

```bash
cargo build -p openshell-driver-kubevirt
```

### 2. Build the container disk image

On an OpenShift cluster with an internal registry:

```bash
# Create namespace for sandbox images
oc new-project openshell-sandboxes

# Create BuildConfig
oc apply -f - <<EOF
apiVersion: build.openshift.io/v1
kind: BuildConfig
metadata:
  name: openshell-sandbox-kubevirt
  namespace: openshell-sandboxes
spec:
  output:
    to:
      kind: ImageStreamTag
      name: openshell-sandbox-kubevirt:latest
  source:
    binary: {}
    type: Binary
  strategy:
    dockerStrategy:
      env:
        - name: BUILDAH_FORMAT
          value: docker
    type: Docker
  resources:
    limits:
      memory: 4Gi
    requests:
      memory: 2Gi
EOF

# Create ImageStream
oc create imagestream openshell-sandbox-kubevirt -n openshell-sandboxes

# Build the openshell-sandbox binary first
cargo build -p openshell-sandbox --release

# Create build context with Dockerfile + binary
TMPDIR=$(mktemp -d)
cp target/release/openshell-sandbox "$TMPDIR/"

cat > "$TMPDIR/Dockerfile" << 'DOCKERFILE'
FROM registry.fedoraproject.org/fedora:42 AS builder
RUN dnf install -y libguestfs-tools-c qemu-img guestfs-tools curl && dnf clean all
RUN curl -L -o /tmp/fedora-cloud.qcow2 \
    "https://download.fedoraproject.org/pub/fedora/linux/releases/42/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-42-1.1.x86_64.qcow2"
COPY openshell-sandbox /tmp/openshell-sandbox
RUN export LIBGUESTFS_BACKEND=direct && \
    qemu-img resize /tmp/fedora-cloud.qcow2 10G && \
    virt-customize -a /tmp/fedora-cloud.qcow2 \
        --install cloud-init,cloud-utils-growpart,iproute,nftables,util-linux-core,openssh-server,openssh-clients \
        --mkdir /opt/openshell/bin \
        --mkdir /etc/openshell \
        --mkdir /etc/openshell-tls/client \
        --mkdir /sandbox \
        --upload /tmp/openshell-sandbox:/opt/openshell/bin/openshell-sandbox \
        --chmod 0755:/opt/openshell/bin/openshell-sandbox \
        --link /opt/openshell/bin/openshell-sandbox:/openshell-sandbox \
        --run-command 'groupadd -g 10001 sandbox || true' \
        --run-command 'useradd -u 10001 -g 10001 -m -s /bin/bash sandbox || true' \
        --run-command 'chown 10001:10001 /sandbox' \
        --run-command 'ssh-keygen -A' \
        --run-command 'systemctl enable sshd' \
        --selinux-relabel

FROM scratch
COPY --from=builder /tmp/fedora-cloud.qcow2 /disk/fedora.qcow2
DOCKERFILE

# Start the build (this takes ~4 minutes)
oc start-build openshell-sandbox-kubevirt \
  --from-dir="$TMPDIR" \
  -n openshell-sandboxes \
  --follow

rm -rf "$TMPDIR"
```

The resulting image will be available at:
```
image-registry.openshift-image-registry.svc:5000/openshell-sandboxes/openshell-sandbox-kubevirt:latest
```

### 3. Run the driver (standalone, dev mode)

```bash
# TCP mode for quick testing with grpcurl
./target/debug/openshell-driver-kubevirt \
  --bind-address 127.0.0.1:50051 \
  --allow-unauthenticated-tcp \
  --default-image image-registry.openshift-image-registry.svc:5000/openshell-sandboxes/openshell-sandbox-kubevirt:latest \
  --sandbox-namespace default \
  --vcpus 2 \
  --memory-mib 2048

# Test with grpcurl
grpcurl -plaintext \
  -import-path proto -proto compute_driver.proto \
  127.0.0.1:50051 openshell.compute.v1.ComputeDriver/GetCapabilities
```

### 4. Run with the gateway (full stack)

```bash
# Terminal 1: Start the driver on a Unix domain socket
./target/debug/openshell-driver-kubevirt \
  --bind-socket /tmp/openshell-sockets/kubevirt.sock \
  --allow-same-uid-peer \
  --default-image image-registry.openshift-image-registry.svc:5000/openshell-sandboxes/openshell-sandbox-kubevirt:latest \
  --sandbox-namespace default \
  --vcpus 2 \
  --memory-mib 2048

# Terminal 2: Start the gateway connected to the driver
./target/debug/openshell-gateway \
  --disable-tls \
  --drivers kubevirt \
  --compute-driver-socket /tmp/openshell-sockets/kubevirt.sock \
  --bind-address 127.0.0.1 \
  --port 17670

# Terminal 3: Create a sandbox through the gateway
grpcurl -plaintext \
  -import-path proto -proto openshell.proto \
  -d '{"name": "my-sandbox", "spec": {"log_level": "info"}}' \
  127.0.0.1:17670 openshell.v1.OpenShell/CreateSandbox

# Check sandbox status
grpcurl -plaintext \
  -import-path proto -proto openshell.proto \
  -d '{"name": "my-sandbox"}' \
  127.0.0.1:17670 openshell.v1.OpenShell/GetSandbox

# Delete sandbox
grpcurl -plaintext \
  -import-path proto -proto openshell.proto \
  -d '{"name": "my-sandbox"}' \
  127.0.0.1:17670 openshell.v1.OpenShell/DeleteSandbox
```

## Standalone Policy Mode

By default, the supervisor inside the VM requires either a gateway connection (`OPENSHELL_ENDPOINT`) or local policy files to start. For testing without a gateway, the driver can embed OPA policy files directly into the cloud-init userdata:

```bash
./target/debug/openshell-driver-kubevirt \
  --bind-socket /tmp/openshell-sockets/kubevirt.sock \
  --allow-same-uid-peer \
  --default-image <image> \
  --sandbox-namespace default \
  --policy-rules crates/openshell-supervisor-network/data/sandbox-policy.rego \
  --policy-data /path/to/policy-data.yaml
```

Minimal policy data YAML for testing:

```yaml
version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /etc]
  read_write: [/sandbox, /tmp, /dev/null]

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies: {}
```

When standalone policy is configured, the driver:
1. Reads the rego + YAML files at startup
2. Embeds them in every sandbox's cloud-init `write_files` (at `/etc/openshell/policy/`)
3. Sets `OPENSHELL_POLICY_RULES` and `OPENSHELL_POLICY_DATA` env vars on the supervisor systemd unit

## CLI Reference

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--bind-address` | `OPENSHELL_COMPUTE_DRIVER_BIND` | — | TCP listen address (dev mode) |
| `--bind-socket` | `OPENSHELL_COMPUTE_DRIVER_SOCKET` | — | Unix domain socket path (production) |
| `--allow-unauthenticated-tcp` | `OPENSHELL_COMPUTE_DRIVER_ALLOW_UNAUTHENTICATED_TCP` | `false` | Allow TCP without peer auth |
| `--allow-same-uid-peer` | `OPENSHELL_COMPUTE_DRIVER_ALLOW_SAME_UID_PEER` | `false` | Allow UDS peers with same UID |
| `--expected-peer-pid` | — | — | Restrict UDS to specific PID |
| `--default-image` | `OPENSHELL_SANDBOX_IMAGE` | `""` | Default containerDisk OCI image |
| `--sandbox-namespace` | `OPENSHELL_SANDBOX_NAMESPACE` | `default` | Kubernetes namespace for VMs |
| `--vcpus` | `OPENSHELL_KUBEVIRT_VCPUS` | `2` | vCPUs per VM |
| `--memory-mib` | `OPENSHELL_KUBEVIRT_MEMORY_MIB` | `2048` | Memory (MiB) per VM |
| `--log-level` | `OPENSHELL_LOG_LEVEL` | `info` | Log level |
| `--policy-rules` | `OPENSHELL_POLICY_RULES` | — | OPA rego file (standalone mode) |
| `--policy-data` | `OPENSHELL_POLICY_DATA` | — | Policy data YAML (standalone mode) |

## How It Works

### Sandbox Creation

1. Gateway calls `CreateSandbox` with a `DriverSandbox` spec
2. Driver generates cloud-init userdata containing:
   - Sandbox identity (`/etc/openshell/sandbox-id`)
   - Systemd unit for `openshell-sandbox.service` with all required env vars
   - Sandbox token (if provided by gateway)
   - Policy files (if standalone mode is configured)
   - `runcmd` to enable and start the supervisor
3. Driver creates a Kubernetes `Secret` with the cloud-init userdata (KubeVirt limits inline userdata to 2048 bytes; the rego file alone is ~28KB)
4. Driver creates a KubeVirt `VirtualMachine` referencing the containerDisk image and the cloud-init Secret via `cloudInitNoCloud.secretRef`
5. KubeVirt boots the VM, cloud-init applies the userdata, and the supervisor starts

### Sandbox Deletion

1. Driver deletes the cloud-init `Secret` (best-effort)
2. Driver deletes the `VirtualMachine` (which cascades to the `VirtualMachineInstance`)

### Status Reporting

The driver watches `VirtualMachineInstance` resources and maps KubeVirt conditions to `DriverCondition` messages for the gateway. The VMI `Ready=True` condition maps to `SANDBOX_PHASE_READY`.

## Known Limitations

- **No cgroup PID limit**: VMs don't expose `pids.max` the same way containers do. The supervisor logs a warning but continues.
- **SELinux in guest agent context**: The `virt_qemu_ga_t` SELinux context blocks most commands from the QEMU guest agent. Use SSH for debugging.
- **Supervisor lifecycle**: Without a gateway holding a session, the supervisor's default entrypoint (`/bin/bash`) exits immediately. The supervisor completes its full setup (network namespace, proxy, Landlock, SSH) but then shuts down. In production, the gateway's `ConnectSupervisor` stream keeps the sandbox alive.

## Development Notes

### Kubeconfig

The driver uses `kube::Config::incluster()` first, falling back to `kube::Config::infer()`. For local development with CRC, you may need a static kubeconfig:

```bash
export KUBECONFIG=/path/to/kubeconfig.yaml
```

If your kubeconfig uses an exec-based credential provider (e.g., CRC), extract the bearer token into a static kubeconfig for background processes.

### Testing with grpcurl

```bash
# Install grpcurl
curl -sL https://github.com/fullstorydev/grpcurl/releases/download/v1.9.3/grpcurl_1.9.3_linux_x86_64.tar.gz | tar xz

# All commands use the compute_driver.proto for direct driver access
# or openshell.proto for gateway access

# Direct driver: Create sandbox
grpcurl -plaintext -import-path proto -proto compute_driver.proto \
  -d '{"sandbox":{"id":"test-001","name":"my-test","namespace":"default","spec":{"log_level":"info"}}}' \
  127.0.0.1:50051 openshell.compute.v1.ComputeDriver/CreateSandbox

# Direct driver: Get sandbox
grpcurl -plaintext -import-path proto -proto compute_driver.proto \
  -d '{"sandbox_name":"my-test"}' \
  127.0.0.1:50051 openshell.compute.v1.ComputeDriver/GetSandbox

# Direct driver: Delete sandbox
grpcurl -plaintext -import-path proto -proto compute_driver.proto \
  -d '{"sandbox_id":"test-001","sandbox_name":"my-test"}' \
  127.0.0.1:50051 openshell.compute.v1.ComputeDriver/DeleteSandbox
```

### File Structure

```
crates/openshell-driver-kubevirt/
├── Cargo.toml
├── README.md          # This file
└── src/
    ├── main.rs        # CLI entry point, UDS/TCP listener, peer auth
    ├── lib.rs         # Public exports
    ├── driver.rs      # Core driver: CRUD, watch, cloud-init generation
    ├── grpc.rs        # ComputeDriver gRPC service implementation
    └── types.rs       # KubeVirt API resource definitions (VM, VMI)
```
