use crate::error::{Result, SandboxError};
use crate::policy::SandboxPolicy;

pub struct SeccompFilter;

impl SeccompFilter {
    /// Applies a seccomp-BPF blocklist derived from `policy.blocked_ops.blocked_syscalls`.
    /// Runs in pre_exec: any failure aborts sandbox startup (fail-closed).
    pub fn apply(policy: &SandboxPolicy) -> Result<()> {
        #[cfg(all(target_os = "linux", feature = "seccomp"))]
        {
            use libseccomp::*;

            let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow).map_err(|e| {
                SandboxError::SetupFailed(format!("Failed to initialize seccomp filter: {}", e))
            })?;

            let blocked: Vec<String> = if policy.blocked_ops.blocked_syscalls.is_empty() {
                [
                    "reboot", "kexec_load", "init_module", "delete_module",
                    "mount", "umount2", "swapon", "swapoff",
                    "ptrace", "process_vm_readv", "process_vm_writev",
                    "keyctl", "request_key", "add_key",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect()
            } else {
                policy.blocked_ops.blocked_syscalls.clone()
            };

            let arch = ScmpArch::native()
                .map_err(|e| SandboxError::SetupFailed(format!("seccomp: native arch unavailable: {}", e)))?;

            for syscall_name in &blocked {
                match ScmpSyscall::from_name(syscall_name) {
                    Ok(syscall) => {
                        filter.add_rule_exact(ScmpAction::Errno(1), syscall).map_err(|e| {
                            SandboxError::SetupFailed(format!(
                                "seccomp: failed to block '{}': {}",
                                syscall_name, e
                            ))
                        })?;
                    }
                    Err(_) => {
                        tracing::debug!("seccomp: syscall '{}' not present on this kernel/arch, skipping", syscall_name);
                        let _ = arch;
                    }
                }
            }

            filter.load().map_err(|e| {
                SandboxError::SetupFailed(format!("Failed to load seccomp filter: {}", e))
            })?;
        }

        #[cfg(all(target_os = "linux", not(feature = "seccomp")))]
        {
            let _ = policy;
            return Err(SandboxError::Unsupported(
                "Built without the 'seccomp' feature; refusing to run without syscall filtering on Linux".into(),
            ));
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = policy;
        }

        Ok(())
    }
}
