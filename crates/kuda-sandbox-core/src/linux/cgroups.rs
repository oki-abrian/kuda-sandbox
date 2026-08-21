use crate::error::{Result, SandboxError};
use crate::policy::ResourcePolicy;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct CgroupManager {
    base_path: PathBuf,
}

impl Default for CgroupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupManager {
    pub fn new() -> Self {
        Self {
            base_path: PathBuf::from("/sys/fs/cgroup/kuda_sandbox"),
        }
    }

    /// Checks if cgroups v2 filesystem is available and writable
    pub fn is_available(&self) -> bool {
        Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
    }

    /// Creates an isolated cgroup directory for a sandbox session
    pub fn create_sandbox_cgroup(&self, id: &Uuid, policy: &ResourcePolicy) -> Result<PathBuf> {
        let cg_path = self.base_path.join(id.to_string());
        fs::create_dir_all(&cg_path).map_err(|e| {
            SandboxError::SetupFailed(format!("Failed to create cgroup dir {}: {}", cg_path.display(), e))
        })?;

        // 1. Set Memory limit (memory.max) — fail-closed: a limit that silently
        //    fails to apply is worse than refusing to start the sandbox.
        if policy.memory_limit_bytes > 0 {
            let mem_file = cg_path.join("memory.max");
            fs::write(mem_file, policy.memory_limit_bytes.to_string()).map_err(|e| {
                SandboxError::SetupFailed(format!("Failed to set cgroup memory.max: {}", e))
            })?;
        }

        // 2. Set Max PIDs (pids.max)
        if policy.max_pids > 0 {
            let pids_file = cg_path.join("pids.max");
            fs::write(pids_file, policy.max_pids.to_string()).map_err(|e| {
                SandboxError::SetupFailed(format!("Failed to set cgroup pids.max: {}", e))
            })?;
        }

        // 3. Set CPU quota (cpu.max) - e.g. 100000 100000 = 100% of 1 core
        let cpu_file = cg_path.join("cpu.max");
        fs::write(cpu_file, "100000 100000").map_err(|e| {
            SandboxError::SetupFailed(format!("Failed to set cgroup cpu.max: {}", e))
        })?;

        Ok(cg_path)
    }

    /// Assigns a PID to the specified cgroup
    pub fn assign_pid(&self, cg_path: &Path, pid: u32) -> Result<()> {
        let procs_file = cg_path.join("cgroup.procs");
        fs::write(procs_file, pid.to_string()).map_err(|e| {
            SandboxError::SetupFailed(format!("Failed to write PID to cgroup.procs: {}", e))
        })?;
        Ok(())
    }

    /// Cleans up and removes the cgroup after execution
    pub fn cleanup_cgroup(&self, cg_path: &Path) -> Result<()> {
        if cg_path.exists() {
            // Write to cgroup.kill to terminate any lingering processes in the cgroup immediately
            let kill_file = cg_path.join("cgroup.kill");
            if kill_file.exists() {
                let _ = fs::write(kill_file, "1");
            }
            let _ = fs::remove_dir_all(cg_path);
        }
        Ok(())
    }
}
