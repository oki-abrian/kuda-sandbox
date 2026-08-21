// Binary wire protocol tests: framing, streaming exec, SCM_RIGHTS fd passing.
use kuda_sandbox_core::wire::{classify_workspace, recv_frame, send_frame, serve_connection, MsgType};
use kuda_sandbox_core::{BinaryClient, ExecEvent, ExecRequest, SandboxError, SandboxExecutor};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;
use uuid::Uuid;

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kuda_wire_{}_{}", tag, Uuid::new_v4()));
    fs::create_dir_all(&d).unwrap();
    d
}

/// Unix socket paths on macOS are limited to 104 chars (SUN_LEN), so sockets
/// live at short names under /tmp while workspaces/files use the long temp dir.
fn short_sock(tag: &str) -> PathBuf {
    let id = Uuid::new_v4().simple().to_string()[..8].to_string();
    PathBuf::from(format!("/tmp/kw_{}_{}.sock", tag, id))
}

async fn socket_pair(tag: &str) -> (UnixStream, UnixStream) {
    let p = short_sock(tag);
    let l = tokio::net::UnixListener::bind(&p).unwrap();
    let c = UnixStream::connect(&p).await.unwrap();
    let (s, _) = l.accept().await.unwrap();
    (c, s)
}

struct TestDaemon {
    sock: PathBuf,
    ws: PathBuf,
}

async fn spawn_daemon(tag: &str) -> TestDaemon {
    let sock = short_sock(tag);
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let executor = SandboxExecutor::new();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let exec = executor.clone();
                tokio::spawn(async move {
                    serve_connection(&exec, stream).await;
                });
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    TestDaemon { sock, ws: temp_dir(tag) }
}

fn make_req(command: &str, ws: &std::path::Path) -> ExecRequest {
    ExecRequest {
        command: command.to_string(),
        workspace: ws.to_string_lossy().to_string(),
        allow_net: false,
        ram_mb: 512,
        timeout_secs: 30,
        stdin_from_fd: false,
    }
}

// ---------------------------------------------------------------------------
// 1. Frame codec roundtrip + validation
// ---------------------------------------------------------------------------
// multi_thread: the 300KB reverse-frame write needs a concurrent reader;
// on the single-thread test runtime write_all would deadlock against itself.
#[tokio::test(flavor = "multi_thread")]
async fn test_01_wire_frame_roundtrip() {
    eprintln!("M1 pair");
    let (mut client, mut server) = socket_pair("roundtrip").await;
    eprintln!("M2 send");
    send_frame(&mut client, MsgType::StdoutChunk, b"hello-binary", None)
        .await
        .unwrap();
    eprintln!("M3 recv");
    let f = tokio::time::timeout(Duration::from_secs(5), recv_frame(&mut server)).await.unwrap().unwrap();
    eprintln!("M4 assert");
    assert_eq!(f.msg_type, MsgType::StdoutChunk);
    assert_eq!(f.payload, b"hello-binary".to_vec());
    assert!(f.fd.is_none());

    // Reverse direction with a large payload (multi-chunk write path)
    let big = vec![0xABu8; 300 * 1024];
    eprintln!("M5 big send");
    let reader = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), recv_frame(&mut client)).await
    });
    send_frame(&mut server, MsgType::StderrChunk, &big, None).await.unwrap();
    eprintln!("M6 big recv");
    let f2 = reader.await.unwrap().unwrap().unwrap();
    eprintln!("M7 done");
    assert_eq!(f2.msg_type, MsgType::StderrChunk);
    assert_eq!(f2.payload.len(), big.len());
}

#[tokio::test]
async fn test_02_wire_rejects_bad_magic_and_oversize() {
    use tokio::io::AsyncWriteExt;
    let (mut client, mut server) = socket_pair("badmagic").await;

    // Garbage magic
    client.write_all(b"XXXX\x01\0\0\0\0\0\0\0\0").await.unwrap();
    let err = recv_frame(&mut server).await.unwrap_err();
    assert!(matches!(err, SandboxError::SecurityViolation(_)), "got: {:?}", err);

    // Oversized declared length
    let mut hdr = b"KUDA".to_vec();
    hdr.push(MsgType::StdoutChunk as u8);
    hdr.extend_from_slice(&u64::MAX.to_le_bytes());
    client.write_all(&hdr).await.unwrap();
    let err2 = recv_frame(&mut server).await.unwrap_err();
    assert!(matches!(err2, SandboxError::SecurityViolation(_)), "got: {:?}", err2);
}

// ---------------------------------------------------------------------------
// 2. Streaming exec over the binary protocol
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_03_binary_exec_streams_output_live() {
    let d = spawn_daemon("stream").await;
    let mut client = BinaryClient::connect(&d.sock).await.unwrap();

    let mut stdout_all = Vec::new();
    let mut stderr_all = Vec::new();
    let mut exit_code: Option<i32> = None;
    let mut saw_metrics = false;

    client
        .exec(
            &make_req("echo hello-stream; echo err-line >&2", &d.ws),
            None,
            |ev| match ev {
                ExecEvent::Stdout(c) => stdout_all.extend_from_slice(&c),
                ExecEvent::Stderr(c) => stderr_all.extend_from_slice(&c),
                ExecEvent::Exit(st) => {
                    exit_code = Some(st.exit_code);
                    saw_metrics = !st.metrics.platform.is_empty() && st.metrics.total_duration_ms > 0;
                }
                ExecEvent::Error(e) => panic!("unexpected error event: {}", e),
            },
        )
        .await
        .unwrap();

    let out = String::from_utf8_lossy(&stdout_all);
    let err = String::from_utf8_lossy(&stderr_all);
    assert!(out.contains("hello-stream"), "stdout: {:?}", out);
    assert!(err.contains("err-line"), "stderr: {:?}", err);
    assert_eq!(exit_code, Some(0));
    assert!(saw_metrics, "exit frame must carry real metrics");
}

// ---------------------------------------------------------------------------
// 3. Zero-copy stdin via SCM_RIGHTS fd passing
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_04_fd_stdin_passing_zero_copy() {
    let d = spawn_daemon("fdstdin").await;

    let input_path = d.ws.join("big_input.txt");
    let payload = format!("FD-PAYLOAD-{}\n", Uuid::new_v4());
    let mut big = payload.repeat(2000); // ~40KB through descriptor, not through frames
    fs::write(&input_path, &mut big).unwrap();

    let mut client = BinaryClient::connect(&d.sock).await.unwrap();
    let mut stdout_all = Vec::new();
    let stderr_probe: std::sync::Arc<std::sync::Mutex<Vec<u8>>> = Default::default();
    let probe_clone = stderr_probe.clone();
    let exit_probe: std::sync::Arc<std::sync::Mutex<Option<i32>>> = Default::default();
    let exit_clone = exit_probe.clone();
    let mut req = make_req("cat", &d.ws);
    req.stdin_from_fd = true;

    client
        .exec(&req, Some(&input_path), |ev| match ev {
            ExecEvent::Stdout(c) => stdout_all.extend_from_slice(&c),
            ExecEvent::Stderr(c) => probe_clone.lock().unwrap().extend_from_slice(&c),
            ExecEvent::Exit(st) => *exit_clone.lock().unwrap() = Some(st.exit_code),
            ExecEvent::Error(e) => panic!("error event: {}", e),
        })
        .await
        .unwrap();

    let out = String::from_utf8_lossy(&stdout_all);
    eprintln!("FDDBG expected={} got={} exit={:?} stderr={:?}",
        big.len(), out.len(), exit_probe, String::from_utf8_lossy(&stderr_probe.lock().unwrap()));
    assert_eq!(out.len(), big.len(), "child must read the exact fd content");
    assert!(out.contains(payload.trim()), "fd content must round-trip intact");
}

// ---------------------------------------------------------------------------
// 4. FILE_GET artifact retrieval via FD handoff + containment
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_05_file_get_fd_handoff_and_containment() {
    let d = spawn_daemon("fileget").await;
    let mut client = BinaryClient::connect(&d.sock).await.unwrap();

    // Create an artifact inside the sandboxed workspace
    client
        .exec(&make_req("printf 'artifact-data-123' > out.txt", &d.ws), None, |_| {})
        .await
        .unwrap();

    let dest = d.ws.join("fetched_local.txt");
    eprintln!("FGDBG fetching {}", d.ws.join("out.txt").display());
    let written = match client
        .fetch_file(d.ws.join("out.txt").to_str().unwrap(), &dest)
        .await
    {
        Ok(w) => w,
        Err(e) => panic!("fetch failed: {}", e),
    };
    assert_eq!(written, "artifact-data-123".len() as u64);
    assert_eq!(fs::read_to_string(&dest).unwrap(), "artifact-data-123");

    // Containment: a path outside this session's workspace must be refused
    let outside = std::env::temp_dir().join(format!("outside_{}.txt", Uuid::new_v4()));
    fs::write(&outside, "secret").unwrap();
    let err = client
        .fetch_file(outside.to_str().unwrap(), &d.ws.join("stolen.txt"))
        .await
        .unwrap_err();
    let msg = format!("{}", err);
    assert!(msg.contains("outside this session's workspace"), "got: {}", msg);

    // And without any exec on a fresh connection, FILE_GET is refused outright
    let mut fresh = BinaryClient::connect(&d.sock).await.unwrap();
    let err2 = fresh
        .fetch_file(outside.to_str().unwrap(), &d.ws.join("stolen2.txt"))
        .await
        .unwrap_err();
    assert!(format!("{}", err2).contains("no workspace established"));
}

// ---------------------------------------------------------------------------
// 5. Workspace guard enforced on the wire path too
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_06_workspace_guard_on_binary_protocol() {
    eprintln!("G1 spawning daemon");
    let d = spawn_daemon("guard").await;
    eprintln!("G2 connecting");
    let mut client = BinaryClient::connect(&d.sock).await.unwrap();
    eprintln!("G3 connected");

    let mut req = make_req("echo pwned", std::path::Path::new("/opt/homebrew"));
    req.workspace = "/opt/homebrew".to_string();

    let mut got_error = String::new();
    eprintln!("G4 exec start");
    client.exec(&req, None, |ev| match ev {
        ExecEvent::Error(e) => got_error = e,
        _ => {}
    }).await.unwrap();
    eprintln!("G5 exec done");

    assert!(got_error.contains("protected"), "expected guard rejection, got: {:?}", got_error);
}

// ---------------------------------------------------------------------------
// 6. classify_workspace sanity (shared by daemon + RPC)
// ---------------------------------------------------------------------------
#[test]
fn test_07_classify_workspace_rules() {
    assert!(classify_workspace(std::path::Path::new("/opt/homebrew")).is_err());
    assert!(classify_workspace(std::path::Path::new("/")).is_err());

    if let Ok(home) = std::env::var("HOME") {
        assert!(classify_workspace(std::path::Path::new(&home)).is_err());
        assert!(classify_workspace(std::path::Path::new(&format!("{}/.ssh/keys", home))).is_err());
    }

    // Deep non-protected paths are allowed
    let ok = std::env::temp_dir().join("kuda_deep").join("project");
    assert!(classify_workspace(&ok).is_ok());
}
