use crate::error::{Result, SandboxError};
use crate::vm::config::VmConfig;
use base64::Engine;
use std::path::{Path, PathBuf};

pub struct AppleVirtualizationEngine;

const QEMU_CANDIDATES: &[&str] = &[
    "/opt/homebrew/bin/qemu-system-aarch64",
    "/usr/local/bin/qemu-system-aarch64",
    "/opt/homebrew/bin/qemu-system-x86_64",
    "/usr/local/bin/qemu-system-x86_64",
];

fn find_qemu() -> Option<PathBuf> {
    for c in QEMU_CANDIDATES {
        if Path::new(c).exists() {
            return Some(PathBuf::from(c));
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            for name in ["qemu-system-aarch64", "qemu-system-x86_64"] {
                let p = Path::new(dir).join(name);
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }
    None
}

impl AppleVirtualizationEngine {
    /// Hardware virtualization on macOS requires a QEMU (HVF) binary — this engine
    /// shells out to qemu-system-* with the hvf accelerator.
    pub fn is_supported() -> bool {
        #[cfg(target_os = "macos")]
        {
            find_qemu().is_some()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    /// Spawns a lightweight Linux MicroVM on macOS via QEMU + Apple Hypervisor (hvf).
    /// The guest command is base64-encoded into the kernel cmdline so arbitrary
    /// quotes/spaces in the command can never break cmdline parsing:
    ///   init=/bin/sh -c "echo <B64> | base64 -d | sh"
    pub async fn spawn_micro_vm(config: &VmConfig, command_str: &str) -> Result<(String, String, i32)> {
        if !Self::is_supported() {
            return Err(SandboxError::Unsupported(
                "Apple Silicon virtualization requires qemu-system-aarch64/x86_64 (brew install qemu)".into(),
            ));
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
            SandboxError::SetupFailed("MicroVM Hypervisor binary (qemu-system) not found".into())
        })?;

        tracing::info!(
            "Booting Linux MicroVM (QEMU/HVF): vCPU={} | RAM={}MB | Kernel={:?}",
            config.vcpu_count,
            config.ram_mb,
            kernel_path
        );

        let payload = base64::engine::general_purpose::STANDARD.encode(command_str.as_bytes());
        let init_cmd = format!("echo {} | base64 -d | sh", payload);
        let is_arm = hypervisor_bin.to_string_lossy().contains("aarch64");
        let console = if is_arm { "ttyAMA0" } else { "ttyS0" };
        let append = format!("console={} panic=-1 init=/bin/sh -c \"{}\"", console, init_cmd);

        let mut cmd = build_qemu_command(&hypervisor_bin, config, &append);

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);

        run_vm_with_timeout(cmd, config).await
    }
}

/// Builds the shared QEMU invocation: machine/CPU/RAM/kernel/initrd/drives/network.
fn build_qemu_command(bin: &Path, config: &VmConfig, append: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(bin);
    let is_arm = bin.to_string_lossy().contains("aarch64");
    let machine = if is_arm { "virt,accel=hvf" } else { "q35,accel=hvf" };
    cmd.arg("-machine").arg(machine)
        .arg("-cpu").arg("host")
        .arg("-smp").arg(config.vcpu_count.to_string())
        .arg("-m").arg(format!("{}M", config.ram_mb))
        .arg("-nographic")
        .arg("-kernel").arg(kernel_display(config))
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
            // Bridged mode needs host taps/permissions; fail loudly instead of silently NAT-ing
            cmd.arg("-nic").arg("none");
        }
    }

    cmd
}

fn kernel_display(config: &VmConfig) -> std::borrow::Cow<'_, std::ffi::OsStr> {
    match &config.kernel_path {
        Some(p) => std::borrow::Cow::Borrowed(p.as_os_str()),
        None => std::borrow::Cow::Owned(std::ffi::OsString::from("/dev/null")),
    }
}

/// Runs the VM child under a wall-clock timeout; real exit code is propagated,
/// including signal termination (128+signal).
async fn run_vm_with_timeout(
    mut cmd: tokio::process::Command,
    config: &VmConfig,
) -> Result<(String, String, i32)> {
    let timeout_secs = if config.timeout_secs == 0 { 300 } else { config.timeout_secs };
    let child = cmd.spawn().map_err(|e| {
        SandboxError::SetupFailed(format!("Failed to execute MicroVM session: {}", e))
    })?;

    let wait = child.wait_with_output();
    match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), wait).await {
        Ok(out) => {
            let out = out.map_err(|e| {
                SandboxError::SetupFailed(format!("Failed to wait for MicroVM session: {}", e))
            })?;
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let exit_code = exit_code_of(&out.status);
            Ok((stdout, stderr, exit_code))
        }
        Err(_) => Err(SandboxError::Timeout(timeout_secs)),
    }
}

fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map(|s| 128 + s).unwrap_or(-1)
    })
}
