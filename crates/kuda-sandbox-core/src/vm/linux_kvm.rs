use crate::error::{Result, SandboxError};
use crate::vm::config::VmConfig;
use base64::Engine;
use std::path::{Path, PathBuf};

pub struct KvmMicroVmEngine;

fn find_qemu() -> Option<PathBuf> {
    let candidates = [
        "/usr/bin/qemu-system-x86_64",
        "/usr/bin/qemu-system-aarch64",
        "/usr/libexec/qemu-kvm",
    ];
    for c in candidates {
        if Path::new(c).exists() {
            return Some(PathBuf::from(c));
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            for name in ["qemu-system-x86_64", "qemu-system-aarch64"] {
                let p = Path::new(dir).join(name);
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }
    None
}

impl KvmMicroVmEngine {
    /// Checks if `/dev/kvm` exists and is accessible
    pub fn is_supported() -> bool {
        #[cfg(target_os = "linux")]
        {
            Path::new("/dev/kvm").exists()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Spawns a Linux KVM MicroVM. The guest command is base64-encoded into the
    /// kernel cmdline so arbitrary quotes/spaces cannot break cmdline parsing:
    ///   init=/bin/sh -c "echo <B64> | base64 -d | sh"
    pub async fn spawn_micro_vm(config: &VmConfig, command_str: &str) -> Result<(String, String, i32)> {
        if !Self::is_supported() {
            return Err(SandboxError::Unsupported("KVM (/dev/kvm) is not available on this host".into()));
        }

        let kernel_path = match &config.kernel_path {
            Some(p) if p.exists() => p,
            Some(p) => {
                return Err(SandboxError::SetupFailed(format!(
                    "Configured kernel_path '{}' does not exist",
                    p.display()
                )))
            }
            None => {
                return Err(SandboxError::SetupFailed(
                    "MicroVM execution requires a valid Linux kernel image (vmlinux/bzImage). Please configure a valid kernel_path in VmConfig.".into()
                ))
            }
        };

        let hypervisor_bin = find_qemu().ok_or_else(|| {
            SandboxError::SetupFailed(
                "KVM Hypervisor binary (qemu-system) not found. Install 'qemu-system-x86' or 'cloud-hypervisor'.".into(),
            )
        })?;

        tracing::info!(
            "Booting KVM Linux MicroVM: vCPU={} | RAM={}MB | Kernel={:?}",
            config.vcpu_count,
            config.ram_mb,
            kernel_path
        );

        let payload = base64::engine::general_purpose::STANDARD.encode(command_str.as_bytes());
        let init_cmd = format!("echo {} | base64 -d | sh", payload);
        let append = format!("console=ttyS0 panic=-1 init=/bin/sh -c \"{}\"", init_cmd);

        let mut cmd = tokio::process::Command::new(&hypervisor_bin);
        cmd.arg("-enable-kvm")
            .arg("-cpu").arg("host")
            .arg("-smp").arg(config.vcpu_count.to_string())
            .arg("-m").arg(format!("{}M", config.ram_mb))
            .arg("-nographic")
            .arg("-kernel").arg(kernel_path)
            .arg("-append").arg(append);

        if let Some(ref initrd) = config.initrd_path {
            cmd.arg("-initrd").arg(initrd);
        }

        for drive in &config.drives {
            let readonly = if drive.is_read_only { ",readonly=on" } else { "" };
            cmd.arg("-drive")
                .arg(format!("file={},format=raw,if=virtio{}", drive.path.display(), readonly));
        }

        match config.network {
            crate::vm::VmNetwork::None => {
                cmd.arg("-nic").arg("none");
            }
            crate::vm::VmNetwork::Nat => {
                cmd.arg("-nic").arg("user,model=virtio-net-pci");
            }
            crate::vm::VmNetwork::Bridged(_) => {
                cmd.arg("-nic").arg("none");
            }
        }

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);

        let timeout_secs = if config.timeout_secs == 0 { 300 } else { config.timeout_secs };
        let child = cmd.spawn().map_err(|e| {
            SandboxError::SetupFailed(format!("Failed to execute KVM MicroVM session: {}", e))
        })?;

        let wait = child.wait_with_output();
        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), wait).await {
            Ok(out) => {
                let out = out.map_err(|e| {
                    SandboxError::SetupFailed(format!("Failed to wait for KVM MicroVM session: {}", e))
                })?;
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                let exit_code = exit_code_of(&out.status);
                Ok((stdout, stderr, exit_code))
            }
            Err(_) => Err(SandboxError::Timeout(timeout_secs)),
        }
    }
}

fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map(|s| 128 + s).unwrap_or(-1)
    })
}
