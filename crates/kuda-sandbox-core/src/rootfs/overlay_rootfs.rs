#[cfg(target_os = "linux")]
use crate::error::{Result, SandboxError};
#[cfg(not(target_os = "linux"))]
use crate::error::Result;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct ContainerFs {
    pub container_id: Uuid,
    pub root_dir: PathBuf,
    pub upper_dir: PathBuf,
    pub work_dir: PathBuf,
    pub workspace_mount: PathBuf,
}

pub struct RootfsOverlayManager {
    base_run_dir: PathBuf,
}

impl Default for RootfsOverlayManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RootfsOverlayManager {
    pub fn new() -> Self {
        Self {
            base_run_dir: PathBuf::from("/tmp/kuda_containers"),
        }
    }

    /// Prepares an isolated container rootfs with ephemeral copy-on-write upper layer
    pub fn spawn_container_fs(&self, base_rootfs: &Path, workspace: &Path) -> Result<ContainerFs> {
        let container_id = Uuid::new_v4();
        let session_dir = self.base_run_dir.join(container_id.to_string());

        let root_dir = session_dir.join("root");
        let upper_dir = session_dir.join("upper");
        let work_dir = session_dir.join("work");

        fs::create_dir_all(&root_dir)?;
        fs::create_dir_all(&upper_dir)?;
        fs::create_dir_all(&work_dir)?;

        let ws_dest = root_dir.join("workspace");
        fs::create_dir_all(&ws_dest)?;

        #[cfg(target_os = "linux")]
        {
            use nix::mount::{mount, MsFlags};
            let opts = format!(
                "lowerdir={},upperdir={},workdir={}",
                base_rootfs.display(),
                upper_dir.display(),
                work_dir.display()
            );

            mount(
                Some("overlay"),
                &root_dir,
                Some("overlay"),
                MsFlags::empty(),
                Some(opts.as_str()),
            ).map_err(|e| {
                SandboxError::SetupFailed(format!("Failed to mount container rootfs: {}", e))
            })?;

            // Bind-mount workspace inside /workspace (fail-closed: child cwd depends on it)
            mount(
                Some(workspace),
                &ws_dest,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            ).map_err(|e| {
                SandboxError::SetupFailed(format!("Failed to bind-mount workspace into container: {}", e))
            })?;

            // Pre-create pivot_root staging dir used by NamespaceManager::enter_container_root
            fs::create_dir_all(root_dir.join(".pivot_old"))?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = base_rootfs;
            let _ = workspace;
        }

        Ok(ContainerFs {
            container_id,
            root_dir,
            upper_dir,
            work_dir,
            workspace_mount: ws_dest,
        })
    }

    /// Destroys the ephemeral container filesystem after completion
    pub fn cleanup(&self, container: &ContainerFs) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use nix::mount::{umount2, MntFlags};
            if container.workspace_mount.exists() {
                let _ = umount2(&container.workspace_mount, MntFlags::MNT_DETACH);
            }
            if container.root_dir.exists() {
                let _ = umount2(&container.root_dir, MntFlags::MNT_DETACH);
            }
        }

        let session_dir = self.base_run_dir.join(container.container_id.to_string());
        if session_dir.exists() {
            let _ = fs::remove_dir_all(session_dir);
        }

        Ok(())
    }
}
