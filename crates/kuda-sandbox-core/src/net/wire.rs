//! Binary wire protocol for the kuda-sandbox daemon (replaces line-delimited JSON).
//!
//! Frame layout (little-endian):
//! ┌────────────┬────────────┬───────────────┬──────────────────────────┐
//! │ Magic 4B   │ Type 1B    │ Length 8B     │ Payload (Length bytes)   │
//! │ "KUDA"     │ MsgType    │ u64           │ raw / JSON               │
//! └────────────┴────────────┴───────────────┴──────────────────────────┘
//!
//! Design notes:
//! - Bulk data (stdout/stderr chunks, file contents) travels as RAW binary —
//!   no base64 inflation, streamed in chunks bounded by MAX_FRAME_LEN.
//! - Structured control payloads (ExecRequest, ExitStatus) are UTF-8 JSON so
//!   third-party clients (Python/Go/Node) need no schema compiler.
//! - Large files never traverse the socket: peers attach an open file
//!   descriptor via Unix SCM_RIGHTS ancillary data (zero-copy handoff).
//!   Only small control frames ever carry fds (ExecRequest, FileGetRequest).
//! Only small control frames ever carry fds (ExecRequest, FileGetRequest).

use crate::error::{Result, SandboxError};
use crate::metrics::ExecutionMetrics;
use crate::policy::NetworkPolicy;
use crate::SandboxExecutor;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

pub const MAGIC: &[u8; 4] = b"KUDA";
pub const HEADER_LEN: usize = 13;
/// Hard cap for a single frame payload (16 MiB). Output is streamed in chunks,
/// so legitimate frames stay far below this.
pub const MAX_FRAME_LEN: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    /// JSON(ExecRequest); may carry an SCM_RIGHTS fd used as child stdin
    ExecRequest = 0x01,
    StdoutChunk = 0x02,
    StderrChunk = 0x03,
    /// JSON(ExitStatus)
    Exit = 0x04,
    /// UTF-8 human-readable error
    Error = 0x05,
    /// UTF-8 absolute path inside an allowed workspace; response carries an SCM_RIGHTS fd
    FileGetRequest = 0x06,
    /// Empty terminator after a FileGetRequest exchange
    FileEof = 0x07,
}

impl MsgType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(MsgType::ExecRequest),
            0x02 => Some(MsgType::StdoutChunk),
            0x03 => Some(MsgType::StderrChunk),
            0x04 => Some(MsgType::Exit),
            0x05 => Some(MsgType::Error),
            0x06 => Some(MsgType::FileGetRequest),
            0x07 => Some(MsgType::FileEof),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: String,
    pub workspace: String,
    pub allow_net: bool,
    pub ram_mb: u64,
    pub timeout_secs: u64,
    /// When true, an SCM_RIGHTS fd accompanies this frame and becomes the child's stdin
    pub stdin_from_fd: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitStatus {
    pub exit_code: i32,
    pub metrics: ExecutionMetrics,
}

/// A decoded frame plus any file descriptor received as ancillary data.
#[derive(Debug)]
pub struct Frame {
    pub msg_type: MsgType,
    pub payload: Vec<u8>,
    pub fd: Option<std::os::unix::io::RawFd>,
}

async fn write_all(stream: &mut UnixStream, buf: &[u8]) -> Result<()> {
    stream.write_all(buf).await.map_err(|e| SandboxError::General(format!("wire write failed: {}", e)))
}

fn encode_header(msg_type: MsgType, len: usize) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(msg_type as u8);
    header.extend_from_slice(&(len as u64).to_le_bytes());
    header
}

/// Sends a frame. When `fd` is provided, it is attached via SCM_RIGHTS so the
/// receiving end gets a dup of the descriptor — no data copying.
pub async fn send_frame(
    stream: &mut UnixStream,
    msg_type: MsgType,
    payload: &[u8],
    fd: Option<std::os::unix::io::RawFd>,
) -> Result<()> {
    if payload.len() as u64 > MAX_FRAME_LEN {
        return Err(SandboxError::General(format!(
            "frame payload {} exceeds MAX_FRAME_LEN {}",
            payload.len(),
            MAX_FRAME_LEN
        )));
    }

    let fd = match fd {
        None => {
            let mut full = encode_header(msg_type, payload.len());
            full.extend_from_slice(payload);
            write_all(stream, &full).await?;
            return Ok(());
        }
        // SAFETY-free: RawFd is Copy; the caller keeps ownership until send completes
        Some(f) => f,
    };

    // Ancillary data rides on the FIRST sendmsg; any remainder goes out as plain bytes.
    use std::os::unix::io::AsRawFd;
    let mut full = encode_header(msg_type, payload.len());
    full.extend_from_slice(payload);
    let raw = stream.as_raw_fd();
    let mut sent = 0usize;
    let mut first = true;

    while sent < full.len() {
        let n = if first {
            let iov = [std::io::IoSlice::new(&full[sent..])];
            let cmsg = [nix::sys::socket::ControlMessage::ScmRights(&[fd])];
            let r = nix::sys::socket::sendmsg::<nix::sys::socket::UnixAddr>(
                raw,
                &iov,
                &cmsg,
                nix::sys::socket::MsgFlags::empty(),
                None,
            )
            .map_err(|e| SandboxError::General(format!("sendmsg with SCM_RIGHTS failed: {}", e)))?;
            first = false;
            r
        } else {
            stream.write_all(&full[sent..]).await.map_err(|e| SandboxError::General(format!("wire write failed: {}", e)))?;
            full.len() - sent
        };
        if n == 0 {
            return Err(SandboxError::General("wire write returned 0".into()));
        }
        sent += n;
    }
    Ok(())
}

/// Reads exactly one frame. Returns Err on bad magic, unknown type or oversized length.
///
/// EVERY frame is read through a recvmsg loop starting at the first byte of the
/// transmission: on SOCK_STREAM, SCM_RIGHTS ancillary data is attached to the
/// leading bytes of a sendmsg, so mixing plain read_exact for the header would
/// silently swallow the descriptor. The loop never over-reads past the frame
/// boundary (recvmsg is capped at the remaining need), keeping frames distinct.
pub async fn recv_frame(stream: &mut UnixStream) -> Result<Frame> {
    use std::os::unix::io::AsRawFd;

    let mut buf: Vec<u8> = Vec::with_capacity(HEADER_LEN + 256);
    let mut need = HEADER_LEN;
    let mut attached_fd: Option<std::os::unix::io::RawFd> = None;
    let raw = stream.as_raw_fd();

    loop {
        stream
            .readable()
            .await
            .map_err(|e| SandboxError::General(format!("readiness failed: {}", e)))?;

        let want = need - buf.len();
        let mut iov = [std::io::IoSliceMut::new(unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr().add(buf.len()), want)
        })];
        let mut cmsg_buf = nix::cmsg_space!([std::os::unix::io::RawFd; 1]);

        // try_io (not raw recvmsg): on WouldBlock it clears tokio's cached
        // readiness, otherwise readable() below resolves instantly and we
        // busy-spin on a single-threaded runtime.
        let result = stream.try_io(tokio::io::Interest::READABLE, || {
            nix::sys::socket::recvmsg::<nix::sys::socket::UnixAddr>(
                raw,
                &mut iov,
                Some(&mut cmsg_buf),
                nix::sys::socket::MsgFlags::empty(),
            )
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
        });

        match result {
            Ok(r) => {
                if r.bytes == 0 {
                    return Err(SandboxError::General("wire stream closed mid-frame".into()));
                }
                if attached_fd.is_none() {
                    if let Ok(cmsgs) = r.cmsgs() {
                        for c in cmsgs {
                            if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = c {
                                if let Some(&f) = fds.first() {
                                    attached_fd = Some(f);
                                }
                            }
                        }
                    }
                }
                unsafe { buf.set_len(buf.len() + r.bytes) };
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(SandboxError::General(format!("recvmsg failed: {}", e))),
        }

        // Parse the header as soon as it is complete to learn the payload length
        if buf.len() >= HEADER_LEN && need == HEADER_LEN {
            if &buf[0..4] != MAGIC {
                return Err(SandboxError::SecurityViolation(format!(
                    "Bad wire magic {:?} — not a kuda binary protocol stream",
                    &buf[0..4]
                )));
            }
            let msg_type_byte = buf[4];
            if MsgType::from_u8(msg_type_byte).is_none() {
                return Err(SandboxError::SecurityViolation(format!(
                    "Unknown wire message type 0x{:02x}",
                    msg_type_byte
                )));
            }
            let len = u64::from_le_bytes(buf[5..13].try_into().unwrap());
            if len > MAX_FRAME_LEN {
                return Err(SandboxError::SecurityViolation(format!(
                    "Frame length {} exceeds protocol cap {}",
                    len, MAX_FRAME_LEN
                )));
            }
            need = HEADER_LEN + len as usize;
            buf.reserve(need - buf.len());
        }

        if buf.len() >= need && buf.len() >= HEADER_LEN {
            let msg_type = MsgType::from_u8(buf[4]).unwrap();
            let payload = buf.split_off(HEADER_LEN);
            return Ok(Frame { msg_type, payload, fd: attached_fd });
        }
    }
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// Serves binary-protocol execution requests on one accepted connection.
/// Output chunks are streamed live to the client; ends when the peer closes.
/// FILE_GET is confined to the workspace established by this connection's
/// most recent successful EXEC_REQUEST — arbitrary host paths are refused.
pub async fn serve_connection(executor: &SandboxExecutor, mut stream: UnixStream) {
    let mut session_workspace: Option<PathBuf> = None;

    loop {
        let frame = match recv_frame(&mut stream).await {
            Ok(f) => f,
            Err(_) => return,
        };

        match frame.msg_type {
            MsgType::ExecRequest => {
                let req: Result<ExecRequest> = serde_json::from_slice(&frame.payload)
                    .map_err(|e| SandboxError::General(format!("bad ExecRequest encoding: {}", e)));
                let ws: Option<PathBuf> = req
                    .ok()
                    .and_then(|r| classify_workspace(Path::new(&r.workspace)).ok())
                    .and_then(|w| w.canonicalize().ok());

                if handle_exec(executor, &mut stream, frame.payload, frame.fd).await.is_err() {
                    return;
                }
                // Only remember the workspace after an accepted request
                if ws.is_some() {
                    session_workspace = ws;
                }
            }
            MsgType::FileGetRequest => {
                if handle_file_get(&mut stream, frame.payload, session_workspace.clone())
                    .await
                    .is_err()
                {
                    return;
                }
            }
            _ => return,
        }
    }
}

async fn handle_exec(
    executor: &SandboxExecutor,
    stream: &mut UnixStream,
    payload: Vec<u8>,
    stdin_fd: Option<std::os::unix::io::RawFd>,
) -> Result<()> {
    let req: ExecRequest = serde_json::from_slice(&payload)
        .map_err(|e| SandboxError::General(format!("bad ExecRequest encoding: {}", e)))?;

    let ws = PathBuf::from(&req.workspace);
    let ws = match classify_workspace(&ws) {
        Ok(ws) => ws,
        Err(reason) => return send_frame(stream, MsgType::Error, reason.as_bytes(), None).await,
    };

    let mut policy = crate::policy::SandboxPolicy::agent_default(ws.clone());
    policy.network = if req.allow_net { NetworkPolicy::AllowAll } else { NetworkPolicy::Deny };
    if req.ram_mb > 0 {
        policy.resources.memory_limit_bytes = req.ram_mb * 1024 * 1024;
    }
    if req.timeout_secs > 0 {
        policy.resources.wall_time_limit_secs = req.timeout_secs;
    }

    let stdin_stdio = stdin_fd.map(|fd| {
        use std::os::unix::io::FromRawFd;
        // Ownership of the received descriptor transfers into Stdio here
        unsafe { std::process::Stdio::from_raw_fd(fd) }
    });

    // Live-stream pipe output to the client as frames
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::executor::OutputChunk>(64);
    let exec_fut = executor.execute_wait_streaming_with_stdin(&req.command, &ws, &policy, stdin_stdio, tx);

    let (exec_res, fwd_res) = tokio::join!(exec_fut, async {
        while let Some(chunk) = rx.recv().await {
            let t = if chunk.is_stdout { MsgType::StdoutChunk } else { MsgType::StderrChunk };
            if send_frame(stream, t, &chunk.data, None).await.is_err() {
                return false;
            }
        }
        true
    });

    if !fwd_res {
        return Err(SandboxError::General("client disconnected during streaming".into()));
    }

    match exec_res {
        Ok(res) => {
            let status = ExitStatus { exit_code: res.exit_code, metrics: res.metrics };
            let encoded = serde_json::to_vec(&status).map_err(|e| SandboxError::General(e.to_string()))?;
            send_frame(stream, MsgType::Exit, &encoded, None).await
        }
        Err(e) => send_frame(stream, MsgType::Error, format!("{}", e).as_bytes(), None).await,
    }
}

async fn handle_file_get(
    stream: &mut UnixStream,
    payload: Vec<u8>,
    session_workspace: Option<PathBuf>,
) -> Result<()> {
    let rel = match String::from_utf8(payload) {
        Ok(p) => p,
        Err(_) => return send_frame(stream, MsgType::Error, b"non-utf8 path".as_slice(), None).await,
    };

    let Some(ws) = &session_workspace else {
        return send_frame(
            stream,
            MsgType::Error,
            b"FILE_GET refused: no workspace established on this connection (run an exec first)".as_slice(),
            None,
        )
        .await;
    };

    let requested = PathBuf::from(rel.trim());
    if let Err(reason) = classify_workspace(&requested) {
        return send_frame(stream, MsgType::Error, reason.as_bytes(), None).await;
    }

    // Containment: the file must live inside this connection's sandboxed workspace
    let Ok(canon) = requested.canonicalize() else {
        let msg = format!("cannot resolve '{}'", requested.display());
        return send_frame(stream, MsgType::Error, msg.as_bytes(), None).await;
    };
    if !canon.starts_with(ws) {
        let msg = format!(
            "Security Error: '{}' is outside this session's workspace '{}'",
            canon.display(),
            ws.display()
        );
        return send_frame(stream, MsgType::Error, msg.as_bytes(), None).await;
    }

    let meta = match std::fs::metadata(&canon) {
        Ok(m) => m,
        Err(e) => {
            let msg = format!("cannot stat '{}': {}", canon.display(), e);
            return send_frame(stream, MsgType::Error, msg.as_bytes(), None).await;
        }
    };
    if !meta.is_file() {
        let msg = format!("'{}' is not a regular file", canon.display());
        return send_frame(stream, MsgType::Error, msg.as_bytes(), None).await;
    }

    let f = match std::fs::File::open(&canon) {
        Ok(f) => f,
        Err(e) => {
            let msg = format!("cannot open '{}': {}", canon.display(), e);
            return send_frame(stream, MsgType::Error, msg.as_bytes(), None).await;
        }
    };

    use std::os::unix::io::AsRawFd;
    let size = meta.len();
    send_frame(stream, MsgType::FileGetRequest, &size.to_le_bytes(), Some(f.as_raw_fd())).await?;
    drop(f);
    send_frame(stream, MsgType::FileEof, &[], None).await
}

/// Prefix-based workspace containment check (shared by CLI daemon and RPC server).
pub fn classify_workspace(canon: &Path) -> std::result::Result<PathBuf, String> {
    let canon_str = canon.to_string_lossy();
    let home = std::env::var("HOME").unwrap_or_default();

    const PROTECTED_ROOTS: &[&str] = &[
        "/", "/private", "/etc", "/private/etc", "/var", "/private/var",
        "/usr", "/bin", "/sbin", "/System", "/Library", "/opt",
        "/opt/homebrew", "/Volumes", "/Users", "/home", "/boot", "/dev",
        "/proc", "/sys", "/private/tmp", "/tmp",
    ];
    if PROTECTED_ROOTS.iter().any(|r| canon_str == *r) {
        return Err(format!("Path '{}' is a protected system/root directory and cannot be mounted as a workspace.", canon.display()));
    }

    let mut protected_prefixes: Vec<PathBuf> = vec![
        PathBuf::from("/etc"),
        PathBuf::from("/private/etc"),
        PathBuf::from("/usr"),
        PathBuf::from("/bin"),
        PathBuf::from("/sbin"),
        PathBuf::from("/System"),
        PathBuf::from("/private/var/root"),
    ];
    if !home.is_empty() {
        let home_path = PathBuf::from(&home);
        for secret in [".ssh", ".gnupg", ".aws", ".config/gcloud", ".kuda_keys"] {
            protected_prefixes.push(home_path.join(secret));
        }
        if canon == home_path {
            return Err(format!("Path '{}' is the user home root and cannot be mounted as a workspace.", canon.display()));
        }
    }
    for p in &protected_prefixes {
        if canon.starts_with(p) {
            return Err(format!("Path '{}' is inside a protected subtree ({}).", canon.display(), p.display()));
        }
    }

    Ok(canon.to_path_buf())
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

pub struct BinaryClient {
    stream: UnixStream,
}

#[derive(Debug)]
pub enum ExecEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(ExitStatus),
    Error(String),
}

impl BinaryClient {
    pub async fn connect(socket_path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(socket_path).await.map_err(|e| {
            SandboxError::SetupFailed(format!("Cannot connect to daemon at {}: {}", socket_path.display(), e))
        })?;
        Ok(Self { stream })
    }

    /// Executes a command remotely, delivering streamed output through `on_event`.
    /// When `stdin_path` is set, that file's descriptor is handed to the daemon
    /// via SCM_RIGHTS (zero-copy) and becomes the remote child's stdin.
    pub async fn exec<F>(&mut self, req: &ExecRequest, stdin_path: Option<&Path>, mut on_event: F) -> Result<()>
    where
        F: FnMut(ExecEvent),
    {
        let payload = serde_json::to_vec(req).map_err(|e| SandboxError::General(e.to_string()))?;

        match stdin_path {
            None => send_frame(&mut self.stream, MsgType::ExecRequest, &payload, None).await?,
            Some(p) => {
                let f = std::fs::File::open(p)
                    .map_err(|e| SandboxError::SetupFailed(format!("Cannot open stdin file {}: {}", p.display(), e)))?;
                use std::os::unix::io::AsRawFd;
                send_frame(&mut self.stream, MsgType::ExecRequest, &payload, Some(f.as_raw_fd())).await?;
                drop(f);
            }
        }

        loop {
            let frame = recv_frame(&mut self.stream).await?;
            match frame.msg_type {
                MsgType::StdoutChunk => on_event(ExecEvent::Stdout(frame.payload)),
                MsgType::StderrChunk => on_event(ExecEvent::Stderr(frame.payload)),
                MsgType::Exit => {
                    let st: ExitStatus = serde_json::from_slice(&frame.payload)
                        .map_err(|e| SandboxError::General(format!("bad ExitStatus encoding: {}", e)))?;
                    on_event(ExecEvent::Exit(st));
                    return Ok(());
                }
                MsgType::Error => {
                    on_event(ExecEvent::Error(String::from_utf8_lossy(&frame.payload).to_string()));
                    return Ok(());
                }
                _ => return Err(SandboxError::General("unexpected frame type in exec session".into())),
            }
        }
    }

    /// Requests a zero-copy FD handoff of a daemon-side file and copies it into
    /// `dest` locally. Returns bytes written.
    pub async fn fetch_file(&mut self, remote_path: &str, dest: &Path) -> Result<u64> {
        send_frame(&mut self.stream, MsgType::FileGetRequest, remote_path.as_bytes(), None).await?;

        let frame = recv_frame(&mut self.stream).await?;
        match frame.msg_type {
            MsgType::Error => Err(SandboxError::General(String::from_utf8_lossy(&frame.payload).to_string())),
            MsgType::FileGetRequest => {
                if frame.payload.len() < 8 {
                    return Err(SandboxError::General("short FILE_GET reply".into()));
                }
                let expected = u64::from_le_bytes(frame.payload[..8].try_into().unwrap());
                let fd = frame.fd.ok_or_else(|| SandboxError::General("daemon did not attach an fd".into()))?;

                use std::os::unix::io::FromRawFd;
                let mut src = unsafe { std::fs::File::from_raw_fd(fd) };
                let mut out = std::fs::File::create(dest)?;
                let written = std::io::copy(&mut src, &mut out)?;

                let _ = recv_frame(&mut self.stream).await?;
                if written != expected {
                    return Err(SandboxError::General(format!("file size mismatch: expected {}, got {}", expected, written)));
                }
                Ok(written)
            }
            _ => Err(SandboxError::General("unexpected reply to FILE_GET".into())),
        }
    }
}
