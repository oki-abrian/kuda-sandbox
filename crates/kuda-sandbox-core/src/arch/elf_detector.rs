use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    X86_64,
    Aarch64,
    ArmV7,
    Riscv64,
    Mips,
    Wasm,
    MachO(String),
    Script,
    Unknown,
}

pub struct ElfDetector;

/// Enough bytes for ELF header (e_machine at 18), Mach-O fat headers, and Java class version
const HEADER_LEN: usize = 64;

impl ElfDetector {
    /// Detects the target CPU architecture of an executable file
    pub fn detect_binary_architecture(path: &Path) -> Result<Architecture> {
        let mut f = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Ok(Architecture::Unknown),
        };

        let mut header = [0u8; HEADER_LEN];
        let bytes_read = match f.read(&mut header) {
            Ok(n) => n,
            Err(_) => return Ok(Architecture::Unknown),
        };

        if bytes_read < 4 {
            return Ok(Architecture::Unknown);
        }

        // 1. Check Shebang (#!)
        if header[0] == b'#' && header[1] == b'!' {
            return Ok(Architecture::Script);
        }

        // 2. Check WebAssembly (\0asm)
        if header[0..4] == [0x00, 0x61, 0x73, 0x6d] {
            return Ok(Architecture::Wasm);
        }

        // 3. Check Mach-O (64/32 bit, little/big endian)
        if header[0..4] == [0xcf, 0xfa, 0xed, 0xfe] || header[0..4] == [0xfe, 0xed, 0xfa, 0xcf] {
            return Ok(Architecture::MachO("64-bit".into()));
        }
        if header[0..4] == [0xce, 0xfa, 0xed, 0xfe] || header[0..4] == [0xfe, 0xed, 0xfa, 0xce] {
            return Ok(Architecture::MachO("32-bit".into()));
        }

        // 4. Universal/Fat binary OR Java class file (both start with 0xCAFEBABE).
        // Disambiguate: a Mach-O fat header stores nfat_arch (1..=16, big-endian) at offset 4,
        // while a Java class file stores minor_version (typically 0..=65535 but almost never
        // a small plausible arch count followed by valid fat entries) — use the count heuristic.
        if header[0..4] == [0xca, 0xfe, 0xba, 0xbe] || header[0..4] == [0xbe, 0xba, 0xfe, 0xca] {
            if bytes_read >= 8 {
                let n = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
                if (1..=16).contains(&n) {
                    return Ok(Architecture::MachO("Universal/Fat".into()));
                }
            }
            return Ok(Architecture::Unknown);
        }

        // 5. Check Linux ELF (\x7fELF) — respect EI_DATA endianness for e_machine
        if header[0..4] == [0x7f, b'E', b'L', b'F'] && bytes_read >= 20 {
            let machine = match header.get(5).copied() {
                Some(2) => u16::from_be_bytes([header[18], header[19]]), // ELFDATA2MSB
                _ => u16::from_le_bytes([header[18], header[19]]),       // ELFDATA2LSB / unknown
            };
            return match machine {
                0x3E => Ok(Architecture::X86_64),   // AMD x86-64
                0xB7 => Ok(Architecture::Aarch64),  // ARM AArch64
                0x28 => Ok(Architecture::ArmV7),    // ARM 32-bit
                0xF3 => Ok(Architecture::Riscv64),  // RISC-V 64
                0x08 => Ok(Architecture::Mips),     // MIPS
                _ => Ok(Architecture::Unknown),
            };
        }

        Ok(Architecture::Unknown)
    }

    /// Gets current host CPU architecture
    pub fn host_architecture() -> Architecture {
        #[cfg(target_arch = "x86_64")]
        return Architecture::X86_64;
        #[cfg(target_arch = "aarch64")]
        return Architecture::Aarch64;
        #[cfg(target_arch = "riscv64")]
        return Architecture::Riscv64;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
        return Architecture::Unknown;
    }

    /// Checks if a binary requires CPU emulation on current host
    pub fn requires_emulation(binary_path: &Path) -> bool {
        if let Ok(arch) = Self::detect_binary_architecture(binary_path) {
            let host = Self::host_architecture();
            match (&arch, &host) {
                (Architecture::X86_64, Architecture::Aarch64) => true,
                (Architecture::Aarch64, Architecture::X86_64) => true,
                (Architecture::ArmV7, _) => true,
                // Native when the host IS the same architecture
                (Architecture::Riscv64, Architecture::Riscv64) => false,
                (Architecture::Riscv64, _) => true,
                _ => false,
            }
        } else {
            false
        }
    }
}
