# 🐎 Kuda Sandbox (`minibox`)
> **A Lightweight, Sub-50ms Secure Code Execution Engine in Rust**  
> *Engineered for Autonomous AI Agents, RLM Kernels, and High-Throughput Isolated Workloads.*

---

## 💡 Overview

**Kuda Sandbox** is a native, zero-container overhead code execution sandbox built from scratch in Rust. It isolates untrusted AI code (Python scripts, shell commands, build pipelines) using low-level Operating System primitives in **under 50 milliseconds**, completely bypassing the heavy startup latency and resource consumption of Docker.

```text
[ AI Agent / Kuda IDE ] 
        │ (Direct Rust Crate Call or Unix Domain Socket)
        ▼
┌────────────────────────────────────────────────────────┐
│  kuda-sandbox (Rust Engine)                            │
│                                                        │
│  1. OverlayFS   ───> Instant Copy-on-Write Filesystem  │
│  2. Namespaces  ───> PID, Mount, Network, IPC, UTS     │
│  3. cgroups v2  ───> Hardware Enforced RAM & CPU Cap   │
│  4. seccomp-BPF ───> Syscall Whitelist (Blocks Root)   │
│  5. Darwin SBPL ───> macOS sandbox-exec Profile Engine │
└────────────────────────────────────────────────────────┘
```

---

## 🛠️ Key Primitives & Architecture

| Primitive | Mechanism | Protection Scope |
|---|---|---|
| **Linux Namespaces** | `unshare(CLONE_NEWPID \| CLONE_NEWNS \| CLONE_NEWNET \| CLONE_NEWUTS)` | Process isolation, empty network loopback, private filesystem tree |
| **cgroups v2** | `/sys/fs/cgroup/...` (`memory.max`, `cpu.max`, `pids.max`) | Prevents OOM crashes, CPU pegging, fork bombs |
| **seccomp-BPF** | Kernel-level Berkeley Packet Filter | Blocks destructive syscalls (`reboot`, `mount`, `kexec`, `ptrace`) |
| **OverlayFS** | Instant layered mounting (`upper`, `lower`, `work`) | Clean copy-on-write workspace in < 1ms |
| **Apple Sandbox** | Scheme-based SBPL profile generation (`sandbox-exec`) | Read-only system paths, strictly workspace-scoped Read-Write |
| **POSIX `setrlimit`** | `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NOFILE` | Universal fallback enforcement on any Unix host |

---

## 🚀 Quickstart CLI (`minibox`)

### Build Workspace
```bash
cargo build --release
```

### 1. Run Python in Sandbox
```bash
./target/release/minibox run "python3 -c 'import os; print(os.listdir(\".\"))'" --ram-mb 512 --timeout 30
```

### 2. Check System Capabilities
```bash
./target/release/minibox info
```

### 3. Start High-Throughput Daemon
```bash
./target/release/minibox daemon --socket /tmp/kuda_sandbox.sock
```

---

## 📦 Using as a Rust Crate

Add to your `Cargo.toml`:
```toml
[dependencies]
kuda-sandbox-core = { path = "path/to/kuda-sandbox/crates/kuda-sandbox-core" }
```

Execute code in 3 lines of Rust:
```rust
use kuda_sandbox_core::{SandboxExecutor, SandboxPolicy};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = PathBuf::from("./my-project");
    let policy = SandboxPolicy::agent_default(workspace.clone());
    let executor = SandboxExecutor::new();

    let result = executor.execute_wait("python3 script.py", &workspace, &policy).await?;
    println!("Output:\n{}", result.stdout);
    println!("Duration: {}ms", result.metrics.execution_duration_ms);

    Ok(())
}
```

---

## 📊 Benchmark Comparison

| Metric | Docker Container | VM / MicroVM | **Kuda Sandbox (`minibox`)** |
|---|---|---|---|
| **Cold Start** | ~1,200 ms | ~300 ms | **< 35 ms** |
| **Memory Baseline** | ~150 MB | ~256 MB | **< 4 MB** |
| **Host Dependencies** | Docker Daemon | Hypervisor | **Zero (Native OS Syscalls)** |
| **Throughput** | ~5 runs/sec | ~10 runs/sec | **> 120 runs/sec** |

---

## 🛡️ Security Policies

- **`agent_default`**: Read-Write strictly to workspace, network disabled (`Deny`), sensitive paths (`~/.ssh`, `~/.gnupg`, `~/.aws`) blocked.
- **`rlm_kernel`**: Read-Only on whole workspace, Read-Write restricted strictly to `.kuda/` scratchpad.
- **`build_mode`**: Outbound network allowed (`npm install`, `pip install`, `cargo build`), extended memory/CPU limits.
