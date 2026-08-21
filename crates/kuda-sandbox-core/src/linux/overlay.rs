use crate::error::{Result, SandboxError};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct OverlayMount {
    pub id: Uuid,
    pub lower_dir: PathBuf,
    pub upper_dir: PathBuf,
    pub work_dir: PathBuf,
    pub merged_dir: PathBuf,
}

pub struct OverlayManager {
    base_tmp: PathBuf,
}

impl Default for OverlayManager {
    fn default() -> Self {
        Self::new()
    }
}

impl OverlayManager {
    pub fn new() -> Self {
        Self {
            base_tmp: PathBuf::from("/tmp/kuda_sandbox_overlay"),
        }
    }

    /// Prepares ephemeral OverlayFS directories for an instant execution layer
    pub fn prepare_overlay(&self, lower_path: &Path) -> Result<OverlayMount> {
        let id = Uuid::new_v4();
        let session_root = self.base_tmp.join(id.to_string());

        let upper = session_root.join("upper");
        let work = session_root.join("work");
        let merged = session_root.join("merged");

        fs::create_dir_all(&upper)?;
        fs::create_dir_all(&work)?;
        fs::create_dir_all(&merged)?;

        #[cfg(target_os = "linux")]
        {
            use nix::mount::{mount, MsFlags};
            let opts = format!(
                "lowerdir={},upperdir={},workdir={}",
                lower_path.display(),
                upper.display(),
                work.display()
            );

            mount(
                Some("overlay"),
                &merged,
                Some("overlay"),
                MsFlags::empty(),
                Some(opts.as_str()),
            ).map_err(|e| {
                SandboxError::SetupFailed(format!("Failed to mount OverlayFS: {}", e))
            })?;
        }

        Ok(OverlayMount {
            id,
            lower_dir: lower_path.to_path_buf(),
            upper_dir: upper,
            work_dir: work,
            merged_dir: merged,
        })
    }

    /// Cleans up overlay mount and ephemeral storage
    pub fn cleanup_overlay(&self, mount: &OverlayMount) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use nix::mount::{umount2, MntFlags};
            if mount.merged_dir.exists() {
                let _ = umount2(&mount.merged_dir, MntFlags::MNT_DETACH);
            }
        }

        let session_root = self.base_tmp.join(mount.id.to_string());
        if session_root.exists() {
            let _ = fs::remove_dir_all(session_root);
        }

        Ok(())
    }
}
