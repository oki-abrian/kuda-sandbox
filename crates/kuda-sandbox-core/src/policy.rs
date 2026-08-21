use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Complete specification of constraints and permissions for a sandbox instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Filesystem access boundaries
    pub fs: FsPolicy,
    /// Network accessibility rules
    pub network: NetworkPolicy,
    /// Resource consumption constraints
    pub resources: ResourcePolicy,
    /// Blocked operations and syscall filters
    pub blocked_ops: BlockedOps,
    /// Whitelist of environment variable names to pass through
    pub env_allowlist: Vec<String>,
    /// Environment variables injected directly into child process
    pub env_inject: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsPolicy {
    /// Paths allowed for Read and Write (typically workspace root only)
    pub rw_paths: Vec<PathBuf>,
    /// Paths allowed for Read Only (system headers, libraries, interpreters)
    pub ro_paths: Vec<PathBuf>,
    /// Paths explicitly denied even if inside ro/rw hierarchy (~/.ssh, ~/.aws, etc.)
    pub deny_paths: Vec<PathBuf>,
    /// Scratch/temp directory assigned to the sandbox
    pub tmp_dir: Option<PathBuf>,
    /// Whether to mount a temporary OverlayFS layer (Linux only)
    pub use_overlay: bool,
    /// Root of an ephemeral container rootfs (Tier 2). When set, the child
    /// process pivots/chroots into this root before execve (Linux: pivot_root,
    /// macOS root: chroot). None means host filesystem (plain process sandbox).
    pub container_root: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkPolicy {
    /// Disallow all networking (default, safest)
    Deny,
    /// Allow outbound connections only to specific host:port targets
    AllowList(Vec<NetworkTarget>),
    /// Allow full network access (e.g. for package managers like npm/pip/cargo)
    AllowAll,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTarget {
    pub host: String,
    pub port: u16,
    pub protocol: NetProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetProtocol {
    Tcp,
    Udp,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePolicy {
    /// Maximum memory in bytes (e.g. 512 MB = 536_870_912)
    pub memory_limit_bytes: u64,
    /// Maximum CPU execution time in seconds
    pub cpu_time_limit_secs: u64,
    /// Maximum wall-clock execution time in seconds
    pub wall_time_limit_secs: u64,
    /// Maximum child processes / threads allowed simultaneously
    pub max_pids: u32,
    /// Maximum single file size writable in bytes (default 100MB)
    pub max_file_size_bytes: u64,
    /// Maximum open file descriptors
    pub max_open_files: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockedOps {
    /// List of Linux syscall names explicitly blocked via seccomp
    pub blocked_syscalls: Vec<String>,
    /// List of custom macOS sandbox profile deny rules
    pub darwin_deny_rules: Vec<String>,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            memory_limit_bytes: 512 * 1024 * 1024, // 512 MB
            cpu_time_limit_secs: 30,               // 30s CPU time
            wall_time_limit_secs: 60,              // 60s Wall time
            max_pids: 64,                          // 64 processes/threads
            max_file_size_bytes: 100 * 1024 * 1024,// 100 MB
            max_open_files: 256,
        }
    }
}

impl SandboxPolicy {
    /// Standard AI Agent execution policy:
    /// - RW access restricted strictly to workspace
    /// - Network disabled (Deny)
    /// - 512 MB RAM, 30s CPU, 60s Wall timeout
    /// - Standard sensitive paths denied
    pub fn agent_default(workspace: PathBuf) -> Self {
        let mut deny_paths = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            let home_p = PathBuf::from(home);
            deny_paths.push(home_p.join(".ssh"));
            deny_paths.push(home_p.join(".gnupg"));
            deny_paths.push(home_p.join(".aws"));
            deny_paths.push(home_p.join(".config/gcloud"));
            deny_paths.push(home_p.join(".kuda_keys"));
        }

        Self {
            fs: FsPolicy {
                rw_paths: vec![workspace],
                ro_paths: vec![
                    PathBuf::from("/usr"),
                    PathBuf::from("/bin"),
                    PathBuf::from("/sbin"),
                    PathBuf::from("/lib"),
                    PathBuf::from("/lib64"),
                    PathBuf::from("/etc/ssl"),
                    PathBuf::from("/etc/resolv.conf"),
                ],
                deny_paths,
                tmp_dir: None,
                use_overlay: false,
                container_root: None,
            },
            network: NetworkPolicy::Deny,
            resources: ResourcePolicy::default(),
            blocked_ops: BlockedOps {
                blocked_syscalls: vec![
                    "reboot".into(),
                    "kexec_load".into(),
                    "init_module".into(),
                    "delete_module".into(),
                    "mount".into(),
                    "umount2".into(),
                    "swapon".into(),
                    "swapoff".into(),
                    "ptrace".into(),
                    "process_vm_readv".into(),
                    "process_vm_writev".into(),
                    "keyctl".into(),
                ],
                darwin_deny_rules: vec![
                    "(deny sysctl-write)".into(),
                    "(deny system-privilege)".into(),
                ],
            },
            env_allowlist: vec![
                "PATH".into(),
                "HOME".into(),
                "LANG".into(),
                "LC_ALL".into(),
                "TERM".into(),
                "USER".into(),
                "SHELL".into(),
            ],
            env_inject: vec![
                ("KUDA_SANDBOX".into(), "1".into()),
                ("PYTHONUNBUFFERED".into(), "1".into()),
            ],
        }
    }

    /// RLM Kernel Execution Policy:
    /// - Read-Only on entire workspace
    /// - Read-Write ONLY inside `.kuda/` directory
    /// - Network disabled
    pub fn rlm_kernel(workspace: PathBuf, kuda_dir: PathBuf) -> Self {
        let mut policy = Self::agent_default(workspace.clone());
        policy.fs.rw_paths = vec![kuda_dir];
        policy.fs.ro_paths.push(workspace);
        policy.network = NetworkPolicy::Deny;
        policy
    }

    /// Package build / install policy (npm, pip, cargo):
    /// - Network enabled
    /// - Increased resource limits (1GB RAM, 120s timeout)
    pub fn build_mode(workspace: PathBuf) -> Self {
        let mut policy = Self::agent_default(workspace);
        policy.network = NetworkPolicy::AllowAll;
        policy.resources.memory_limit_bytes = 1024 * 1024 * 1024; // 1 GB
        policy.resources.wall_time_limit_secs = 180;              // 3 min
        policy.resources.cpu_time_limit_secs = 120;
        policy
    }
}
