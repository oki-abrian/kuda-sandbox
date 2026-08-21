use crate::error::{Result, SandboxError};
use crate::policy::SandboxPolicy;
use std::path::Path;

pub struct NamespaceManager;

impl NamespaceManager {
    /// Configures Linux namespaces for the child process.
    /// This should be executed in the pre_exec closure before invoking execve.
    pub fn setup_child_namespaces(policy: &SandboxPolicy, _working_dir: &Path) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use nix::sched::{unshare, CloneFlags};

            let mut flags = CloneFlags::CLONE_NEWNS  // Mount namespace
                | CloneFlags::CLONE_NEWPID          // PID namespace
                | CloneFlags::CLONE_NEWIPC          // IPC namespace
                | CloneFlags::CLONE_NEWUTS;         // UTS hostname namespace

            // If network is completely denied, isolate into empty loopback-only netns
            if policy.network == crate::policy::NetworkPolicy::Deny {
                flags |= CloneFlags::CLONE_NEWNET;
            }

            // Attempt unshare
            unshare(flags).map_err(|e| {
                SandboxError::SetupFailed(format!("Failed to unshare Linux namespaces: {}", e))
            })?;

            // Make mount namespace strictly private to prevent mount leaking to host
            use nix::mount::{mount, MsFlags};
            let _ = mount(
                None::<&str>,
                "/",
                None::<&str>,
                MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                None::<&str>,
            );

            // Set sandbox hostname (UTS ns is fresh, so this cannot affect the host)
            let _ = nix::unistd::sethostname("kuda-sandbox");

            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = policy;
            let _ = _working_dir;
            Ok(())
        }
    }

    /// Enters an ephemeral container rootfs via pivot_root (fail-closed).
    /// Must run after CLONE_NEWNS + MS_PRIVATE, and BEFORE the seccomp filter
    /// is loaded (pivot/umount/mount syscalls are blocked by the filter).
    pub fn enter_container_root(root: &Path) -> Result<()> {
        use nix::mount::{mount, umount2, MntFlags, MsFlags};
        use nix::unistd::{chdir, mkdir};

        // 1. cwd into new root and make it a bind mount (pivot_root requires a mount point)
        chdir(root).map_err(|e| {
            SandboxError::SetupFailed(format!("Container root {} is not accessible: {}", root.display(), e))
        })?;
        mount(
            Some(root),
            root,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| SandboxError::SetupFailed(format!("Failed to rebind container root: {}", e)))?;

        // 2. pivot_root(root, root/.pivot_old) then detach the old host root
        let put_old = root.join(".pivot_old");
        if !put_old.exists() {
            mkdir(&put_old, nix::sys::stat::Mode::from_bits_truncate(0o700)).map_err(|e| {
                SandboxError::SetupFailed(format!("Failed to create .pivot_old dir: {}", e))
            })?;
        }

        let root_c = path_to_cstring(root)?;
        let old_c = path_to_cstring(&put_old)?;

        let rc = unsafe { libc::pivot_root(root_c.as_ptr(), old_c.as_ptr()) };
        if rc != 0 {
            return Err(SandboxError::SetupFailed(format!(
                "pivot_root into {} failed: {}",
                root.display(),
                std::io::Error::last_os_error()
            )));
        }

        chdir("/").map_err(|e| SandboxError::SetupFailed(format!("chdir(/) after pivot failed: {}", e)))?;
        umount2("/.pivot_old", MntFlags::MNT_DETACH)
            .map_err(|e| SandboxError::SetupFailed(format!("Failed to detach old host root: {}", e)))?;
        let _ = nix::unistd::rmdir("/.pivot_old");

        // 3. Mount a fresh /proc so PID-namespace visibility works inside the container
        let _ = mount(
            Some("proc"),
            "/proc",
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            None::<&str>,
        );

        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn path_to_cstring(p: &Path) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(p.as_os_str().as_bytes())
        .map_err(|e| SandboxError::SetupFailed(format!("Invalid path '{}': {}", p.display(), e)))
}
