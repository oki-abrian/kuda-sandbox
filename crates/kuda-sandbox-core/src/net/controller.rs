use crate::error::Result;
use crate::net::chaos::ChaosProfile;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum NetworkCommand {
    /// Update network latency and packet loss on-the-fly
    SetChaos {
        latency_ms: u64,
        jitter_ms: Option<u64>,
        packet_loss: f32,
    },
    /// Cut off connection completely (Network Partition / Split-Brain)
    SetPartition {
        blocked: bool,
    },
    /// Bandwidth throttling
    SetBandwidth {
        kbps: u64,
    },
    /// Reset network back to normal pristine state
    Reset,
    /// Get current network metrics
    GetStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatusResponse {
    pub latency_ms: u64,
    pub packet_loss: f32,
    pub partition_active: bool,
    pub bandwidth_kbps: Option<u64>,
}

#[derive(Clone)]
pub struct DynamicNetworkController {
    current_chaos: Arc<RwLock<ChaosProfile>>,
    partition_active: Arc<RwLock<bool>>,
    socket_path: PathBuf,
}

impl DynamicNetworkController {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            current_chaos: Arc::new(RwLock::new(ChaosProfile::default())),
            partition_active: Arc::new(RwLock::new(false)),
            socket_path,
        }
    }

    pub fn socket_path(&self) -> &PathBuf {
        &self.socket_path
    }

    /// Starts the runtime control socket listener for dynamic script mutations.
    /// Protocol: newline-delimited JSON (one command per line, one JSON reply per line).
    pub async fn start_control_listener(&self) -> Result<()> {
        if self.socket_path.exists() {
            remove_stale_socket_if_owned(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600));
        }
        let chaos_state = self.current_chaos.clone();
        let partition_state = self.partition_active.clone();

        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let c_state = chaos_state.clone();
                    let p_state = partition_state.clone();

                    tokio::spawn(async move {
                        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                        let (read_half, mut write_half) = tokio::io::split(stream);
                        let mut reader = BufReader::new(read_half);
                        let mut line_buf = String::new();

                        while let Ok(n) = reader.read_line(&mut line_buf).await {
                            if n == 0 {
                                break;
                            }

                            let trimmed = line_buf.trim().to_string();
                            line_buf.clear();
                            if trimmed.is_empty() {
                                continue;
                            }

                            match serde_json::from_str::<NetworkCommand>(&trimmed) {
                                Ok(cmd) => {
                                    let reply = handle_network_command(cmd, &c_state, &p_state).await;
                                    let _ = write_half.write_all(format!("{}\n", reply).as_bytes()).await;
                                }
                                Err(e) => {
                                    let err = serde_json::json!({
                                        "status": "error",
                                        "error": format!("Invalid JSON command: {}", e)
                                    });
                                    let _ = write_half.write_all(format!("{}\n", err).as_bytes()).await;
                                }
                            }
                        }
                    });
                }
            }
        });

        Ok(())
    }
}

/// Removes a leftover socket file only if it is a socket owned by the current user.
fn remove_stale_socket_if_owned(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let meta = std::fs::metadata(path).map_err(|e| {
        crate::error::SandboxError::General(format!(
            "Cannot stat existing control socket {}: {}",
            path.display(),
            e
        ))
    })?;

    if !meta.file_type().is_socket() {
        return Err(crate::error::SandboxError::SecurityViolation(format!(
            "Refusing to delete '{}': it exists but is not a socket",
            path.display()
        )));
    }

    let euid = nix::unistd::Uid::effective().as_raw();
    if meta.uid() != euid {
        return Err(crate::error::SandboxError::SecurityViolation(format!(
            "Refusing to delete control socket '{}' owned by uid {} (current uid {})",
            path.display(),
            meta.uid(),
            euid
        )));
    }

    std::fs::remove_file(path)
        .map_err(|e| crate::error::SandboxError::General(format!("Failed to remove stale socket: {}", e)))
}

async fn handle_network_command(
    cmd: NetworkCommand,
    c_state: &Arc<RwLock<ChaosProfile>>,
    p_state: &Arc<RwLock<bool>>,
) -> serde_json::Value {
    match cmd {
        NetworkCommand::SetChaos { latency_ms, jitter_ms, packet_loss } => {
            let mut state = c_state.write().await;
            state.latency_ms = latency_ms;
            state.jitter_ms = jitter_ms.unwrap_or(0);
            state.packet_loss = packet_loss;
            serde_json::json!({ "status": "ok", "applied": "set_chaos" })
        }
        NetworkCommand::SetPartition { blocked } => {
            let mut p = p_state.write().await;
            *p = blocked;
            serde_json::json!({ "status": "ok", "applied": "set_partition" })
        }
        NetworkCommand::SetBandwidth { kbps } => {
            let mut state = c_state.write().await;
            state.bandwidth_kbps = Some(kbps);
            serde_json::json!({ "status": "ok", "applied": "set_bandwidth" })
        }
        NetworkCommand::Reset => {
            let mut state = c_state.write().await;
            *state = ChaosProfile::default();
            let mut p = p_state.write().await;
            *p = false;
            serde_json::json!({ "status": "ok", "applied": "reset" })
        }
        NetworkCommand::GetStatus => {
            let state = c_state.read().await;
            let p = *p_state.read().await;
            serde_json::to_value(NetworkStatusResponse {
                latency_ms: state.latency_ms,
                packet_loss: state.packet_loss,
                partition_active: p,
                bandwidth_kbps: state.bandwidth_kbps,
            })
            .unwrap_or_else(|_| serde_json::json!({ "status": "error", "error": "serialization failed" }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_dynamic_network_control_flow() {
        let sock_path = PathBuf::from(format!("/tmp/kuda_test_ctrl_{}.sock", std::process::id()));
        let controller = DynamicNetworkController::new(sock_path.clone());
        controller.start_control_listener().await.unwrap();

        // Give listener a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect client and send mutation (NDJSON: newline-terminated)
        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let cmd = NetworkCommand::SetChaos {
            latency_ms: 120,
            jitter_ms: Some(15),
            packet_loss: 0.05,
        };
        let mut payload = serde_json::to_vec(&cmd).unwrap();
        payload.push(b'\n');
        client.write_all(&payload).await.unwrap();

        let mut resp_buf = vec![0u8; 1024];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(resp_str.contains("ok"));

        // Invalid JSON must get an explicit error reply (no silent drop)
        let mut client_bad = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        client_bad.write_all(b"this is not json\n").await.unwrap();
        let mut err_buf = vec![0u8; 1024];
        let ne = client_bad.read(&mut err_buf).await.unwrap();
        let err_str = String::from_utf8_lossy(&err_buf[..ne]);
        assert!(err_str.contains("\"error\""), "expected error reply, got: {}", err_str);

        // Verify status
        let mut client2 = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let get_cmd = NetworkCommand::GetStatus;
        let mut get_payload = serde_json::to_vec(&get_cmd).unwrap();
        get_payload.push(b'\n');
        client2.write_all(&get_payload).await.unwrap();

        let mut status_buf = vec![0u8; 1024];
        let n2 = client2.read(&mut status_buf).await.unwrap();
        let status: NetworkStatusResponse = serde_json::from_slice(&status_buf[..n2]).unwrap();
        assert_eq!(status.latency_ms, 120);
        assert_eq!(status.packet_loss, 0.05);

        let _ = std::fs::remove_file(sock_path);
    }
}
