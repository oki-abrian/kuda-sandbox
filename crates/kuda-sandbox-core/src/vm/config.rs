use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Number of virtual CPU cores
    pub vcpu_count: u32,
    /// RAM allocated in Megabytes (e.g. 512 MB)
    pub ram_mb: u64,
    /// Path to the uncompressed Linux kernel (vmlinux)
    pub kernel_path: Option<PathBuf>,
    /// Path to the initial ramdisk (initrd)
    pub initrd_path: Option<PathBuf>,
    /// Kernel boot command line arguments
    pub boot_args: String,
    /// VirtIO block drives attached to the VM
    pub drives: Vec<VmDisk>,
    /// Virtual network configuration
    pub network: VmNetwork,
    /// Wall-clock timeout for the whole VM session in seconds (0 = default 300s)
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmDisk {
    pub drive_id: String,
    pub path: PathBuf,
    pub is_read_only: bool,
    pub is_root_device: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VmNetwork {
    None,
    Nat,
    Bridged(String),
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            ram_mb: 512,
            kernel_path: None,
            initrd_path: None,
            boot_args: "console=hvc0 root=/dev/vda rw panic=-1 init=/bin/sh".to_string(),
            drives: Vec::new(),
            network: VmNetwork::Nat,
            timeout_secs: default_timeout(),
        }
    }
}
