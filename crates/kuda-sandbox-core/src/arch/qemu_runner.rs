use crate::arch::elf_detector::{Architecture, ElfDetector};
use std::path::Path;

pub struct QemuRunner;

impl QemuRunner {
    fn find_emulator(name: &str) -> Option<String> {
        let candidates = [format!("{}-static", name), name.to_string()];
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in path_var.split(':') {
                for candidate in &candidates {
                    if Path::new(dir).join(candidate).exists() {
                        return Some(candidate.clone());
                    }
                }
            }
        }
        None
    }

    /// Wraps a command with the appropriate QEMU user-mode emulator if cross-arch is detected
    pub fn wrap_if_needed(command: &str, target_arch: Option<Architecture>) -> String {
        let host = ElfDetector::host_architecture();

        match (target_arch, host) {
            // Running x86_64 binary on Apple Silicon ARM64 host
            (Some(Architecture::X86_64), Architecture::Aarch64) => {
                #[cfg(target_os = "macos")]
                {
                    // Check if Rosetta 2 translation is available
                    if Path::new("/usr/libexec/rosetta/oahd").exists() || Path::new("/Library/Apple/usr/libexec/oah/libRosettaRuntime").exists() {
                        format!("arch -x86_64 {}", command)
                    } else if let Some(emu) = Self::find_emulator("qemu-x86_64") {
                        format!("{} {}", emu, command)
                    } else {
                        command.to_string()
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    if let Some(emu) = Self::find_emulator("qemu-x86_64") {
                        format!("{} {}", emu, command)
                    } else {
                        command.to_string()
                    }
                }
            }
            // Running ARM64 binary on Intel x86_64 host
            (Some(Architecture::Aarch64), Architecture::X86_64) => {
                if let Some(emu) = Self::find_emulator("qemu-aarch64") {
                    format!("{} {}", emu, command)
                } else {
                    command.to_string()
                }
            }
            // Running RISC-V binary on any host
            (Some(Architecture::Riscv64), _) => {
                if let Some(emu) = Self::find_emulator("qemu-riscv64") {
                    format!("{} {}", emu, command)
                } else {
                    command.to_string()
                }
            }
            _ => command.to_string(),
        }
    }
}
