use crate::error::{Result, SandboxError};
use crate::metrics::ExecutionMetrics;
use crate::policy::SandboxPolicy;
use std::path::Path;
#[allow(unused_imports)]
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

/// A live output chunk emitted while the sandboxed process is still running.
#[derive(Debug, Clone)]
pub struct OutputChunk {
    pub is_stdout: bool,
    pub data: Vec<u8>,
}

const CHUNK_BUF_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct SandboxResult {
    pub id: Uuid,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub metrics: ExecutionMetrics,
}

#[derive(Clone)]
pub struct SandboxExecutor {
    #[cfg(target_os = "linux")]
    cgroups: Arc<crate::linux::CgroupManager>,
    #[cfg(target_os = "linux")]
    overlay: Arc<crate::linux::OverlayManager>,
}

impl Default for SandboxExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxExecutor {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            cgroups: Arc::new(crate::linux::CgroupManager::new()),
            #[cfg(target_os = "linux")]
            overlay: Arc::new(crate::linux::OverlayManager::new()),
        }
    }

    /// Builds the platform command with env scrubbing and fail-closed pre-exec hooks.
    fn build_command(&self, command_str: &str, working_dir: &Path, policy: &SandboxPolicy) -> tokio::process::Command {
        #[cfg(target_os = "macos")]
        let mut cmd = crate::darwin::DarwinSandbox::build_command(policy, command_str, working_dir);

        #[cfg(target_os = "linux")]
        let mut cmd = {
            let mut c = tokio::process::Command::new("sh");
            c.arg("-c").arg(command_str);
            c.current_dir(working_dir);
            c
        };

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let mut cmd = {
            let mut c = tokio::process::Command::new("sh");
            c.arg("-c").arg(command_str);
            c.current_dir(working_dir);
            c
        };

        // Strict Environment Variable Scrubbing (Cegah kebocoran token host)
        cmd.env_clear();
        let mut has_path = false;
        for key in &policy.env_allowlist {
            if let Ok(val) = std::env::var(key) {
                if key == "PATH" {
                    has_path = true;
                }
                cmd.env(key, val);
            }
        }
        if !has_path {
            cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin");
        }
        for (k, v) in &policy.env_inject {
            cmd.env(k, v);
        }

        // Pre-exec hooks (Process Group + POSIX setrlimit + Linux Namespaces/Seccomp - Fail Closed)
        #[cfg(unix)]
        {
            let res_policy = policy.resources.clone();
            #[allow(unused_variables)]
            let p_clone = policy.clone();
            #[allow(unused_variables)]
            let w_clone = working_dir.to_path_buf();

            unsafe {
                cmd.pre_exec(move || {
                    // Isolate process group (setpgid) so entire process tree can be killed cleanly
                    let _ = nix::unistd::setpgid(nix::unistd::Pid::from_raw(0), nix::unistd::Pid::from_raw(0));

                    // Apply POSIX setrlimit (Fail-closed)
                    if let Err(e) = crate::resource_limits::apply_setrlimit(&res_policy) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!("Sandbox setup failed: resource limit enforcement error: {}", e),
                        ));
                    }

                    // Apply Linux namespaces & seccomp (Fail-closed)
                    #[cfg(target_os = "linux")]
                    {
                        if let Err(e) = crate::linux::NamespaceManager::setup_child_namespaces(&p_clone, &w_clone) {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!("Sandbox setup failed: namespace isolation error: {}", e),
                            ));
                        }
                        // Enter ephemeral container rootfs (Tier 2) BEFORE seccomp loads,
                        // because pivot/mount syscalls are blocked by the filter.
                        if let Some(root) = &p_clone.fs.container_root {
                            if let Err(e) = crate::linux::NamespaceManager::enter_container_root(root) {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    format!("Sandbox setup failed: container rootfs entry error: {}", e),
                                ));
                            }
                        }
                        if let Err(e) = crate::linux::SeccompFilter::apply(&p_clone) {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                format!("Sandbox setup failed: seccomp filter error: {}", e),
                            ));
                        }
                    }

                    Ok(())
                });
            }
        }

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);

        cmd
    }

    /// Executes a command in a hardened, isolated sandbox environment and waits for output.
    pub async fn execute_wait(
        &self,
        command_str: &str,
        working_dir: &Path,
        policy: &SandboxPolicy,
    ) -> Result<SandboxResult> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<OutputChunk>(64);

        let exec_fut = self.execute_wait_streaming_with_stdin(command_str, working_dir, policy, None, tx);

        let collector = async {
            let mut stdout: Vec<u8> = Vec::new();
            let mut stderr: Vec<u8> = Vec::new();
            while let Some(chunk) = rx.recv().await {
                if chunk.is_stdout {
                    stdout.extend_from_slice(&chunk.data);
                } else {
                    stderr.extend_from_slice(&chunk.data);
                }
            }
            (stdout, stderr)
        };

        let (res, (stdout_b, stderr_b)) = tokio::join!(exec_fut, collector);
        res.map(|mut r| {
            r.stdout = String::from_utf8_lossy(&stdout_b).to_string();
            r.stderr = String::from_utf8_lossy(&stderr_b).to_string();
            r
        })
    }

    /// Streaming execution: pipe output is forwarded as [`OutputChunk`]s through
    /// `chunk_tx` while the process runs. `stdin_stdio` optionally wires an
    /// arbitrary stdin source (e.g. an SCM_RIGHTS-received descriptor).
    pub async fn execute_wait_streaming_with_stdin(
        &self,
        command_str: &str,
        working_dir: &Path,
        policy: &SandboxPolicy,
        stdin_stdio: Option<std::process::Stdio>,
        chunk_tx: tokio::sync::mpsc::Sender<OutputChunk>,
    ) -> Result<SandboxResult> {
        let sandbox_id = Uuid::new_v4();
        let start_time = Instant::now();

        let mut cmd = self.build_command(command_str, working_dir, policy);

        if let Some(si) = stdin_stdio {
            cmd.stdin(si);
        }

        #[cfg(target_os = "linux")]
        let cg_path = if self.cgroups.is_available() {
            Some(self.cgroups.create_sandbox_cgroup(&sandbox_id, &policy.resources)?)
        } else {
            tracing::warn!("cgroups v2 unavailable on this host: memory/pid limits degrade to rlimits only");
            None
        };

        let mut child = cmd.spawn().map_err(|e| {
            SandboxError::SetupFailed(format!("Failed to spawn sandboxed child process: {}", e))
        })?;

        let child_pid = child.id();

        #[cfg(target_os = "linux")]
        if let (Some(ref cg), Some(pid)) = (&cg_path, child_pid) {
            if let Err(e) = self.cgroups.assign_pid(cg, pid) {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;
                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
                let _ = self.cgroups.cleanup_cgroup(cg);
                return Err(e);
            }
        }

        let setup_duration = start_time.elapsed().as_millis() as u64;
        let exec_start = Instant::now();

        // Forward both pipes concurrently while the process runs
        let mut stdout_pipe = child.stdout.take();
        let mut stderr_pipe = child.stderr.take();

        let tx_out = chunk_tx.clone();
        let reader_out = tokio::spawn(async move {
            if let Some(pipe) = stdout_pipe.as_mut() {
                let mut buf = vec![0u8; CHUNK_BUF_SIZE];
                loop {
                    match pipe.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx_out.send(OutputChunk { is_stdout: true, data: buf[..n].to_vec() }).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        let tx_err = chunk_tx.clone();
        let reader_err = tokio::spawn(async move {
            if let Some(pipe) = stderr_pipe.as_mut() {
                let mut buf = vec![0u8; CHUNK_BUF_SIZE];
                loop {
                    match pipe.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx_err.send(OutputChunk { is_stdout: false, data: buf[..n].to_vec() }).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        drop(chunk_tx);

        // Run process with timeout & process group tree killer
        let timeout_secs = policy.resources.wall_time_limit_secs.max(1);
        let wait_res = tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), child.wait()).await;

        let total_duration = start_time.elapsed().as_millis() as u64;
        let exec_duration = exec_start.elapsed().as_millis() as u64;

        #[cfg(target_os = "linux")]
        if let Some(ref cg) = cg_path {
            let _ = self.cgroups.cleanup_cgroup(cg);
        }

        let status = match wait_res {
            Ok(Ok(st)) => st,
            Ok(Err(e)) => {
                let _ = reader_out.await;
                let _ = reader_err.await;
                return Err(SandboxError::SetupFailed(format!("Failed to wait for sandbox child: {}", e)));
            }
            Err(_) => {
                // Timeout fired: Kill the entire isolated process group (killpg)
                if let Some(pid) = child_pid {
                    #[cfg(unix)]
                    {
                        use nix::sys::signal::{kill, Signal};
                        use nix::unistd::Pid;
                        // Negative PID sends SIGKILL to all processes in the PGID
                        let _ = kill(Pid::from_raw(-(pid as i32)), Signal::SIGKILL);
                        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
                    }
                }
                let _ = reader_out.await;
                let _ = reader_err.await;
                return Err(SandboxError::Timeout(timeout_secs));
            }
        };

        // Pipes reach EOF around child exit; give readers a moment to flush tails
        let _ = reader_out.await;
        let _ = reader_err.await;

        #[cfg(unix)]
        let exit_code = status.code().unwrap_or_else(|| {
            use std::os::unix::process::ExitStatusExt;
            status.signal().map(|s| 128 + s).unwrap_or(-1)
        });
        #[cfg(not(unix))]
        let exit_code = status.code().unwrap_or(-1);

        let peak_memory_bytes = measure_peak_memory(
            #[cfg(target_os = "linux")]
            cg_path.as_deref(),
        );

        let platform_name = if cfg!(target_os = "macos") {
            "macOS (Apple Sandbox SBPL + setrlimit)".to_string()
        } else if cfg!(target_os = "linux") {
            "Linux (Namespaces + cgroups v2 + seccomp)".to_string()
        } else {
            "Generic (setrlimit fallback)".to_string()
        };

        Ok(SandboxResult {
            id: sandbox_id,
            exit_code,
            stdout: String::new(),
            stderr: String::new(),
            metrics: ExecutionMetrics {
                sandbox_id,
                setup_duration_ms: setup_duration,
                execution_duration_ms: exec_duration,
                total_duration_ms: total_duration,
                peak_memory_bytes,
                exit_code,
                platform: platform_name,
                resource_violation: if exit_code == 137 {
                    Some("Process killed by SIGKILL (OOM or force kill)".to_string())
                } else if exit_code == 139 {
                    Some("Process terminated by SIGSEGV (Segmentation fault)".to_string())
                } else {
                    None
                },
            },
        })
    }

    /// Executes a command inside an isolated ephemeral RootFS container layer (Tier 2 Container Engine)
    pub async fn execute_container(
        &self,
        command_str: &str,
        working_dir: &Path,
        rootfs_image: &crate::rootfs::RootfsImage,
        policy: &SandboxPolicy,
    ) -> Result<SandboxResult> {
        let img_mgr = crate::rootfs::ImageManager::new();
        let rootfs_base = img_mgr.pull_image(rootfs_image).await?;
        let overlay_mgr = crate::rootfs::RootfsOverlayManager::new();
        let container_fs = overlay_mgr.spawn_container_fs(&rootfs_base, working_dir)?;

        let mut container_policy = policy.clone();
        container_policy.fs.rw_paths.push(container_fs.root_dir.clone());
        container_policy.fs.ro_paths.push(rootfs_base.clone());
        // Pivot target: the child process enters this root before execve.
        container_policy.fs.container_root = Some(container_fs.root_dir.clone());

        // On Linux the workspace is bind-mounted at <new-root>/workspace and the
        // child cwd must live inside the new root (host cwd vanishes after pivot).
        #[cfg(target_os = "linux")]
        let child_cwd = container_fs.workspace_mount.clone();
        #[cfg(not(target_os = "linux"))]
        let child_cwd = working_dir.to_path_buf();

        #[cfg(not(target_os = "linux"))]
        tracing::warn!(
            "Container engine on this OS runs host binaries under the SBPL write-jail only; \
             full rootfs isolation requires Linux (pivot_root) or root privileges."
        );

        let res = self.execute_wait(command_str, &child_cwd, &container_policy).await;

        // Cleanup ephemeral container layer
        let _ = overlay_mgr.cleanup(&container_fs);

        res
    }

    /// Executes a command inside a dedicated Hardware-Isolated MicroVM (Tier 3 MicroVM Engine)
    pub async fn execute_microvm(
        &self,
        command_str: &str,
        config: &crate::vm::VmConfig,
    ) -> Result<SandboxResult> {
        let sandbox_id = Uuid::new_v4();
        let start_time = Instant::now();

        #[cfg(target_os = "macos")]
        let (stdout, stderr, exit_code) = crate::vm::AppleVirtualizationEngine::spawn_micro_vm(config, command_str).await?;

        #[cfg(target_os = "linux")]
        let (stdout, stderr, exit_code) = crate::vm::KvmMicroVmEngine::spawn_micro_vm(config, command_str).await?;

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        return Err(SandboxError::Unsupported("Hardware virtualization is not supported on this OS".into()));

        let total_duration = start_time.elapsed().as_millis() as u64;

        Ok(SandboxResult {
            id: sandbox_id,
            exit_code,
            stdout,
            stderr,
            metrics: ExecutionMetrics {
                sandbox_id,
                setup_duration_ms: 0,
                execution_duration_ms: total_duration,
                total_duration_ms: total_duration,
                peak_memory_bytes: 0,
                exit_code,
                platform: "QEMU Hypervisor (HVF / KVM)".into(),
                resource_violation: None,
            },
        })
    }
}

/// Peak RSS of the finished child: cgroup memory.peak on Linux, getrusage(RUSAGE_CHILDREN) elsewhere.
#[cfg(target_os = "linux")]
fn measure_peak_memory(cg_path: Option<&Path>) -> u64 {
    if let Some(cg) = cg_path {
        if let Ok(s) = std::fs::read_to_string(cg.join("memory.peak")) {
            if let Ok(v) = s.trim().parse::<u64>() {
                return v;
            }
        }
    }
    rusage_children_maxrss()
}

#[cfg(not(target_os = "linux"))]
fn measure_peak_memory() -> u64 {
    rusage_children_maxrss()
}

#[cfg(unix)]
fn rusage_children_maxrss() -> u64 {
    use nix::libc;
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_CHILDREN, &mut ru) == 0 {
            // Linux reports KiB, macOS reports bytes
            #[cfg(target_os = "macos")]
            return ru.ru_maxrss as u64;
            #[cfg(not(target_os = "macos"))]
            return (ru.ru_maxrss as u64).saturating_mul(1024);
        }
    }
    0
}

#[cfg(not(unix))]
fn rusage_children_maxrss() -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sandbox_execution() {
        let executor = SandboxExecutor::new();
        let ws = std::env::current_dir().unwrap();
        let policy = SandboxPolicy::agent_default(ws.clone());
        let res = executor.execute_wait("echo 'sandbox_ok'", &ws, &policy).await.unwrap();
        println!("TEST STDOUT: {:?}", res.stdout);
        println!("TEST STDERR: {:?}", res.stderr);
        println!("TEST EXIT: {:?}", res.exit_code);
        assert_eq!(res.exit_code, 0);
        assert!(res.stdout.contains("sandbox_ok"));
    }

    #[tokio::test]
    async fn test_streaming_chunks_arrive_before_exit() {
        let executor = SandboxExecutor::new();
        let ws = std::env::current_dir().unwrap();
        let policy = SandboxPolicy::agent_default(ws.clone());
        let (tx, mut rx) = tokio::sync::mpsc::channel::<OutputChunk>(16);

        let exec = executor.execute_wait_streaming_with_stdin("echo stream-me", &ws, &policy, None, tx);
        let collector = async {
            let mut got = String::new();
            while let Some(c) = rx.recv().await {
                got.push_str(&String::from_utf8_lossy(&c.data));
            }
            got
        };
        let (res, streamed) = tokio::join!(exec, collector);
        assert_eq!(res.unwrap().exit_code, 0);
        assert!(streamed.contains("stream-me"), "chunks must be observable live, got: {:?}", streamed);
    }
}
