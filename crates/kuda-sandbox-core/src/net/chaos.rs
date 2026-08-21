use crate::error::{Result, SandboxError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChaosProfile {
    /// Injected network latency in milliseconds
    pub latency_ms: u64,
    /// Random jitter in milliseconds
    pub jitter_ms: u64,
    /// Packet loss probability (0.0 to 1.0, e.g. 0.05 = 5% packet loss)
    pub packet_loss: f32,
    /// Bandwidth rate limit in Kilobits per second (e.g. 1024 = 1 Mbps)
    pub bandwidth_kbps: Option<u64>,
    /// Corrupted packets ratio (0.0 to 1.0)
    pub corrupt_ratio: f32,
}

impl ChaosProfile {
    pub fn is_active(&self) -> bool {
        self.latency_ms > 0
            || self.jitter_ms > 0
            || self.packet_loss > 0.0
            || self.bandwidth_kbps.is_some()
            || self.corrupt_ratio > 0.0
    }
}

pub struct NetworkChaosSimulator;

impl NetworkChaosSimulator {
    /// Applies traffic control rules (Linux tc netem) to the given interface.
    /// Uses `qdisc replace` so repeated application never fails with EEXIST.
    /// Requires CAP_NET_ADMIN (typically root). Returns an error on failure —
    /// callers must not report chaos as "active" when this fails.
    pub fn apply_chaos(profile: &ChaosProfile, interface: &str) -> Result<()> {
        if !profile.is_active() {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            let mut netem_args: Vec<String> = Vec::new();

            if profile.latency_ms > 0 {
                let mut delay = format!("{}ms", profile.latency_ms);
                if profile.jitter_ms > 0 {
                    delay = format!("{} {}ms", delay, profile.jitter_ms);
                }
                netem_args.push("delay".into());
                netem_args.push(delay);
            }
            if profile.packet_loss > 0.0 {
                netem_args.push("loss".into());
                netem_args.push(format!("{:.2}%", profile.packet_loss * 100.0));
            }
            if let Some(kbps) = profile.bandwidth_kbps {
                netem_args.push("rate".into());
                netem_args.push(format!("{}kbit", kbps));
            }
            if profile.corrupt_ratio > 0.0 {
                netem_args.push("corrupt".into());
                netem_args.push(format!("{:.2}%", profile.corrupt_ratio * 100.0));
            }

            let mut cmd = std::process::Command::new("tc");
            cmd.args(["qdisc", "replace", "dev", interface, "root", "netem"]);
            cmd.args(&netem_args);

            let out = cmd.output().map_err(|e| {
                SandboxError::SetupFailed(format!(
                    "Failed to run 'tc' (is iproute2 installed? do you have CAP_NET_ADMIN?): {}",
                    e
                ))
            })?;

            if !out.status.success() {
                return Err(SandboxError::SetupFailed(format!(
                    "tc qdisc replace failed on '{}': {}",
                    interface,
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }

            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = interface;
            Err(SandboxError::Unsupported(
                "Network chaos simulation requires Linux tc netem; it is not available on this OS".into(),
            ))
        }
    }

    /// Removes the root netem qdisc, restoring pristine interface behavior.
    /// Missing qdisc is treated as success (idempotent cleanup).
    pub fn clear_chaos(interface: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let out = std::process::Command::new("tc")
                .args(["qdisc", "del", "dev", interface, "root"])
                .output();

            match out {
                Ok(o) if o.status.success() => Ok(()),
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    if stderr.contains("No such file or directory") || stderr.contains("Cannot find requested qdisc") {
                        Ok(())
                    } else {
                        Err(SandboxError::General(format!(
                            "tc qdisc del failed on '{}': {}",
                            interface,
                            stderr.trim()
                        )))
                    }
                }
                Err(e) => Err(SandboxError::General(format!("Failed to run 'tc': {}", e))),
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = interface;
            Ok(())
        }
    }
}
