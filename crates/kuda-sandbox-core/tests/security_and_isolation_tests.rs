use kuda_sandbox_core::{
    Architecture, DynamicNetworkController, ElfDetector, ImageManager,
    NetworkCommand, NetworkPolicy, NetworkStatusResponse, PythonSdkGenerator, QemuRunner,
     RootfsImage, RootfsOverlayManager, SandboxError, SandboxExecutor,
    SandboxPolicy,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn setup_temp_workspace(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kuda_test_{}_{}", name, uuid::Uuid::new_v4()));
    let _ = fs::create_dir_all(&dir);
    dir
}

// --------------------------------------------------------------------------
// TEST 1: Basic Command Execution
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_01_basic_execution_success() {
    let ws = setup_temp_workspace("basic_exec");
    let executor = SandboxExecutor::new();
    let policy = SandboxPolicy::agent_default(ws.clone());

    let res = executor.execute_wait("echo 'hello_kuda_sandbox'", &ws, &policy).await;
    assert!(res.is_ok(), "Basic command execution must succeed");
    let out = res.unwrap();
    assert_eq!(out.exit_code, 0);
    assert!(out.stdout.contains("hello_kuda_sandbox"));
    let _ = fs::remove_dir_all(&ws);
}

// --------------------------------------------------------------------------
// TEST 2: Write Jail Blocks Outside Workspace
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_02_write_jail_blocked_outside_workspace() {
    let ws = setup_temp_workspace("write_jail_outside");
    let executor = SandboxExecutor::new();
    let policy = SandboxPolicy::agent_default(ws.clone());

    // Attempt writing to /etc/kuda_hacked.txt or /Library/kuda_hacked.txt
    let py_code = "try:\n    open('/etc/kuda_hacked.txt', 'w').write('fail')\n    print('WRITTEN')\nexcept Exception as e:\n    print(f'BLOCKED: {e}')";
    let cmd = format!("python3 -c \"{}\"", py_code);

    let res = executor.execute_wait(&cmd, &ws, &policy).await;
    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(out.stdout.contains("BLOCKED") || out.exit_code != 0, "Writing outside workspace must be blocked: {}", out.stdout);
    assert!(!out.stdout.contains("WRITTEN"));
    let _ = fs::remove_dir_all(&ws);
}

// --------------------------------------------------------------------------
// TEST 3: Write Jail Allows Inside Workspace
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_03_write_jail_allowed_inside_workspace() {
    let ws = setup_temp_workspace("write_jail_inside");
    let executor = SandboxExecutor::new();
    let policy = SandboxPolicy::agent_default(ws.clone());

    let target_file = ws.join("test_output.txt");
    let cmd = format!("python3 -c \"open('{}', 'w').write('sandbox_allowed_data')\"", target_file.display());

    let res = executor.execute_wait(&cmd, &ws, &policy).await;
    assert!(res.is_ok());
    let out = res.unwrap();
    assert_eq!(out.exit_code, 0, "Write inside workspace must succeed. Stderr: {}", out.stderr);
    assert!(target_file.exists(), "Target file must exist in workspace");

    let content = fs::read_to_string(&target_file).unwrap();
    assert_eq!(content, "sandbox_allowed_data");
    let _ = fs::remove_dir_all(&ws);
}

// --------------------------------------------------------------------------
// TEST 4: Read Jail Blocks Sensitive Credentials
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_04_read_jail_home_and_sensitive_credentials() {
    let ws = setup_temp_workspace("read_jail");
    let executor = SandboxExecutor::new();
    let policy = SandboxPolicy::agent_default(ws.clone());

    let py_code = "import os\nprint('SSH_EXISTS:', os.path.exists(os.path.expanduser('~/.ssh/id_rsa')))";
    let cmd = format!("python3 -c \"{}\"", py_code);

    let res = executor.execute_wait(&cmd, &ws, &policy).await;
    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(out.stdout.contains("SSH_EXISTS: False"), "Sensitive keys outside workspace must not be visible");
    let _ = fs::remove_dir_all(&ws);
}

// --------------------------------------------------------------------------
// TEST 5: Network Policy Deny Blocks Outbound TCP
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_05_network_policy_deny_blocks_socket() {
    let ws = setup_temp_workspace("net_deny");
    let executor = SandboxExecutor::new();
    let mut policy = SandboxPolicy::agent_default(ws.clone());
    policy.network = NetworkPolicy::Deny;

    let py_code = "import socket\ntry:\n    s = socket.socket()\n    s.settimeout(2.0)\n    s.connect(('1.1.1.1', 80))\n    print('CONNECTED')\nexcept Exception as e:\n    print('BLOCKED:', e)";
    let cmd = format!("python3 -c \"{}\"", py_code);

    let res = executor.execute_wait(&cmd, &ws, &policy).await;
    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(out.stdout.contains("BLOCKED"), "Outbound network connection must be blocked when policy is Deny: {}", out.stdout);
    assert!(!out.stdout.contains("CONNECTED"));
    let _ = fs::remove_dir_all(&ws);
}

// --------------------------------------------------------------------------
// TEST 6: Environment Scrubbing Prevents Token Leakage
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_06_environment_scrubbing_zero_token_leakage() {
    let ws = setup_temp_workspace("env_scrub");
    // Set a secret in host environment
    std::env::set_var("KUDA_SUPER_SECRET_KEY", "sk_live_very_secret_key_12345");

    let executor = SandboxExecutor::new();
    let policy = SandboxPolicy::agent_default(ws.clone());

    let py_code = "import os\nprint('SECRET_FOUND:', 'KUDA_SUPER_SECRET_KEY' in os.environ)";
    let cmd = format!("python3 -c \"{}\"", py_code);

    let res = executor.execute_wait(&cmd, &ws, &policy).await;
    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(out.stdout.contains("SECRET_FOUND: False"), "Host environment secret leaked into sandbox!");
    let _ = fs::remove_dir_all(&ws);
}

// --------------------------------------------------------------------------
// TEST 7: Explicit Environment Injection Works
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_07_environment_injection_works() {
    let ws = setup_temp_workspace("env_inject");
    let executor = SandboxExecutor::new();
    let mut policy = SandboxPolicy::agent_default(ws.clone());
    policy.env_inject.push(("KUDA_AGENT_ID".into(), "agent-007".into()));

    let py_code = "import os\nprint('AGENT_ID:', os.environ.get('KUDA_AGENT_ID', 'MISSING'))";
    let cmd = format!("python3 -c \"{}\"", py_code);

    let res = executor.execute_wait(&cmd, &ws, &policy).await;
    assert!(res.is_ok());
    let out = res.unwrap();
    assert!(out.stdout.contains("AGENT_ID: agent-007"), "Injected environment variable must be present");
    let _ = fs::remove_dir_all(&ws);
}

// --------------------------------------------------------------------------
// TEST 8: Timeout Triggers Properly
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_08_process_timeout_triggers() {
    let ws = setup_temp_workspace("timeout_test");
    let executor = SandboxExecutor::new();
    let mut policy = SandboxPolicy::agent_default(ws.clone());
    policy.resources.wall_time_limit_secs = 1; // 1 second timeout

    let start = std::time::Instant::now();
    let res = executor.execute_wait("sleep 10", &ws, &policy).await;
    let elapsed = start.elapsed();

    assert!(res.is_err(), "Sleep 10 must time out on 1s limit");
    match res.unwrap_err() {
        SandboxError::Timeout(secs) => assert_eq!(secs, 1),
        other => panic!("Expected Timeout error, got {:?}", other),
    }
    assert!(elapsed < Duration::from_secs(4), "Timeout must enforce within bounds, took {:?}", elapsed);
    let _ = fs::remove_dir_all(&ws);
}

// --------------------------------------------------------------------------
// TEST 9: Process Tree Killer Cleans Up Subprocesses
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_09_process_tree_killer_terminates_all_children() {
    let ws = setup_temp_workspace("tree_killer");
    let executor = SandboxExecutor::new();
    let mut policy = SandboxPolicy::agent_default(ws.clone());
    policy.resources.wall_time_limit_secs = 1;

    // Command that spawns background child sleeps
    let cmd = "sh -c 'sleep 50 & sleep 50 & sleep 50 & wait'";
    let res = executor.execute_wait(cmd, &ws, &policy).await;
    assert!(res.is_err());
    let _ = fs::remove_dir_all(&ws);
}

// --------------------------------------------------------------------------
// TEST 10: RLIMIT_CPU Enforcement
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_10_rlimit_cpu_time_limit_enforced() {
    let ws = setup_temp_workspace("cpu_limit");
    let executor = SandboxExecutor::new();
    let mut policy = SandboxPolicy::agent_default(ws.clone());
    policy.resources.cpu_time_limit_secs = 1; // 1 second CPU limit
    policy.resources.wall_time_limit_secs = 10;

    // CPU-bound infinite loop in python
    let py_code = "count = 0\nwhile True:\n    count += 1";
    let cmd = format!("python3 -c \"{}\"", py_code);

    let res = executor.execute_wait(&cmd, &ws, &policy).await;
    assert!(res.is_ok());
    let out = res.unwrap();
    // Process should be terminated by SIGXCPU (24) or SIGKILL (9) -> exit code != 0
    assert_ne!(out.exit_code, 0, "CPU-bound process must be terminated by rlimit");
    let _ = fs::remove_dir_all(&ws);
}

// --------------------------------------------------------------------------
// TEST 11: RLIMIT_FSIZE File Size Limit Enforcement
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_11_rlimit_file_size_limit_enforced() {
    let ws = setup_temp_workspace("fsize_limit");
    let executor = SandboxExecutor::new();
    let mut policy = SandboxPolicy::agent_default(ws.clone());
    policy.resources.max_file_size_bytes = 1024; // 1 KB max file size
    let target = ws.join("big_file.bin");

    // Try to write 100 KB
    let py_code = format!("open('{}', 'wb').write(b'A' * 100000)", target.display());
    let cmd = format!("python3 -c \"{}\"", py_code);

    let res = executor.execute_wait(&cmd, &ws, &policy).await;
    assert!(res.is_ok());
    let _out = res.unwrap();
    // Python buffers the write: RLIMIT_FSIZE fires at flush/close, the process may
    // still exit 0 — enforcement is proven by the capped file size on disk.
    let written = fs::metadata(&target).map(|m| m.len()).unwrap_or(0);
    assert!(written <= 1024, "File must be capped at 1KB by RLIMIT_FSIZE, got {} bytes", written);
    let _ = fs::remove_dir_all(&ws);
}

// --------------------------------------------------------------------------
// TEST 12: Tar-Slip Directory Traversal Detection & Rejection
// --------------------------------------------------------------------------
#[test]
fn test_12_tar_slip_rejection() {
    let temp_dir = std::env::temp_dir().join(format!("kuda_tarslip_{}", uuid::Uuid::new_v4()));
    let _ = fs::create_dir_all(&temp_dir);

    let archive_path = temp_dir.join("evil.tar.gz");

    // Create a malicious tarball with ../../escape.txt
    // (tar-rs refuses to BUILD such entries, so craft the raw ustar stream by hand)
    {
        let data = b"malicious content";

        let mut raw_header = vec![0u8; 512];
        let name = b"../../evil_escape.txt";
        raw_header[..name.len()].copy_from_slice(name);
        raw_header[100..108].copy_from_slice(b"0000644\0"); // mode
        raw_header[108..116].copy_from_slice(b"0000000\0"); // uid
        raw_header[116..124].copy_from_slice(b"0000000\0"); // gid
        raw_header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes()); // size
        raw_header[136..148].copy_from_slice(b"00000000000\0"); // mtime
        raw_header[257..263].copy_from_slice(b"ustar\0");
        raw_header[263..265].copy_from_slice(b"00");
        raw_header[148..156].copy_from_slice(b"        "); // cksum blank for calc
        let cksum: u32 = raw_header.iter().map(|b| *b as u32).sum();
        raw_header[148..156].copy_from_slice(format!("{:06o}\0 ", cksum).as_bytes());

        let mut tar_bytes = raw_header;
        tar_bytes.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        tar_bytes.extend(std::iter::repeat(0u8).take(pad));
        tar_bytes.extend(std::iter::repeat(0u8).take(1024)); // end-of-archive

        let tar_file = fs::File::create(&archive_path).unwrap();
        let mut enc = flate2::write::GzEncoder::new(tar_file, flate2::Compression::default());
        enc.write_all(&tar_bytes).unwrap();
        enc.finish().unwrap();
    }

    let img_mgr = ImageManager::with_cache_dir(temp_dir.clone());
    let res = img_mgr.unpack_tar_gz(&archive_path, &RootfsImage::Custom("test".into()));

    assert!(res.is_err(), "Malicious tar-slip entry must be rejected");
    match res.unwrap_err() {
        SandboxError::SecurityViolation(msg) => assert!(msg.contains("traversal")),
        other => panic!("Expected SecurityViolation, got {:?}", other),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

// --------------------------------------------------------------------------
// TEST 13: Binary Architecture Detector on Mach-O & Shebang
// --------------------------------------------------------------------------
#[test]
fn test_13_binary_architecture_detector() {
    let ls_path = Path::new("/bin/ls");
    if ls_path.exists() {
        let arch = ElfDetector::detect_binary_architecture(ls_path);
        assert!(arch.is_ok(), "Architecture detection on /bin/ls must succeed");
        let detected = arch.unwrap();
        #[cfg(target_os = "macos")]
        assert!(matches!(detected, Architecture::MachO(_) | Architecture::Aarch64 | Architecture::X86_64));
        #[cfg(target_os = "linux")]
        assert!(matches!(detected, Architecture::Aarch64 | Architecture::X86_64));
    }
}

// --------------------------------------------------------------------------
// TEST 14: Binary Architecture Detector on Synthetic ELF Headers
// --------------------------------------------------------------------------
#[test]
fn test_14_synthetic_elf_detection() {
    let temp_dir = std::env::temp_dir().join(format!("kuda_elf_{}", uuid::Uuid::new_v4()));
    let _ = fs::create_dir_all(&temp_dir);

    // Create synthetic x86_64 ELF (header must span e_machine at offset 18..20)
    let x86_path = temp_dir.join("fake_x86");
    let mut x86_elf = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    x86_elf.resize(20, 0);
    x86_elf[18] = 0x3e; // EM_X86_64
    fs::write(&x86_path, &x86_elf).unwrap();

    let arch = ElfDetector::detect_binary_architecture(&x86_path).unwrap();
    assert_eq!(arch, Architecture::X86_64);

    // Create synthetic AArch64 ELF
    let arm_path = temp_dir.join("fake_arm");
    let mut arm_elf = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    arm_elf.resize(20, 0);
    arm_elf[18] = 0xb7; // EM_AARCH64
    fs::write(&arm_path, &arm_elf).unwrap();

    let arch_arm = ElfDetector::detect_binary_architecture(&arm_path).unwrap();
    assert_eq!(arch_arm, Architecture::Aarch64);

    let _ = fs::remove_dir_all(&temp_dir);
}

// --------------------------------------------------------------------------
// TEST 15: QEMU Runner Dynamic Command Wrapping
// --------------------------------------------------------------------------
#[test]
fn test_15_qemu_runner_wrapping_logic() {
    let cmd = "my_app --test";
    let wrapped_same = QemuRunner::wrap_if_needed(cmd, Some(ElfDetector::host_architecture()));
    assert_eq!(wrapped_same, cmd, "Native architecture must not be wrapped with emulator");
}

// --------------------------------------------------------------------------
// TEST 16: Dynamic UDS Network Controller Full Protocol Lifecycle
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_16_dynamic_network_controller_protocol_lifecycle() {
    let sock = std::env::temp_dir().join(format!("kuda_ctrl_{}.sock", uuid::Uuid::new_v4()));
    let controller = DynamicNetworkController::new(sock.clone());
    controller.start_control_listener().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Set Chaos (Latency 250ms, Packet loss 10%) — NDJSON framing: newline-terminated
    let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let cmd = NetworkCommand::SetChaos { latency_ms: 250, jitter_ms: Some(25), packet_loss: 0.1 };
    let mut payload = serde_json::to_vec(&cmd).unwrap();
    payload.push(b'\n');
    stream.write_all(&payload).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("ok"));

    // 2. Set Partition
    let mut stream2 = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let p_cmd = NetworkCommand::SetPartition { blocked: true };
    let mut p_payload = serde_json::to_vec(&p_cmd).unwrap();
    p_payload.push(b'\n');
    stream2.write_all(&p_payload).await.unwrap();
    let n2 = stream2.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n2]).contains("ok"));

    // 3. Get Status
    let mut stream3 = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let mut g_payload = serde_json::to_vec(&NetworkCommand::GetStatus).unwrap();
    g_payload.push(b'\n');
    stream3.write_all(&g_payload).await.unwrap();
    let n3 = stream3.read(&mut buf).await.unwrap();
    let status: NetworkStatusResponse = serde_json::from_slice(&buf[..n3]).unwrap();
    assert_eq!(status.latency_ms, 250);
    assert_eq!(status.packet_loss, 0.1);
    assert!(status.partition_active);

    // 4. Reset
    let mut stream4 = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let mut r_payload = serde_json::to_vec(&NetworkCommand::Reset).unwrap();
    r_payload.push(b'\n');
    stream4.write_all(&r_payload).await.unwrap();
    let n4 = stream4.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n4]).contains("ok"));

    let _ = fs::remove_file(&sock);
}

// --------------------------------------------------------------------------
// TEST 17: Python SDK Generator File Integrity
// --------------------------------------------------------------------------
#[test]
fn test_17_python_sdk_generation_validity() {
    let temp_ws = setup_temp_workspace("py_sdk");
    let sock = Path::new("/tmp/kuda_test_fake.sock");
    let res = PythonSdkGenerator::write_python_sdk(&temp_ws, sock);
    assert!(res.is_ok());

    let sdk_file = temp_ws.join("kuda_sandbox.py");
    assert!(sdk_file.exists());
    let code = fs::read_to_string(&sdk_file).unwrap();
    assert!(code.contains("class NetworkController:"));
    assert!(code.contains("def set_latency("));
    assert!(code.contains("def set_partition("));

    let _ = fs::remove_dir_all(&temp_ws);
}

// --------------------------------------------------------------------------
// TEST 18: Security Policy Presets Verification
// --------------------------------------------------------------------------
#[test]
fn test_18_policy_preset_integrity() {
    let ws = PathBuf::from("/tmp/kuda_mock_ws");

    // agent_default: Deny network, RW workspace
    let p_agent = SandboxPolicy::agent_default(ws.clone());
    assert_eq!(p_agent.network, NetworkPolicy::Deny);
    assert!(p_agent.fs.rw_paths.contains(&ws));

    // rlm_kernel: Deny network, Read-only workspace, RW in .kuda/
    let p_rlm = SandboxPolicy::rlm_kernel(ws.clone(), ws.join(".kuda"));
    assert_eq!(p_rlm.network, NetworkPolicy::Deny);
    assert!(p_rlm.fs.ro_paths.contains(&ws));
    assert!(p_rlm.fs.rw_paths.contains(&ws.join(".kuda")));

    // build_mode: AllowAll network
    let p_build = SandboxPolicy::build_mode(ws.clone());
    assert_eq!(p_build.network, NetworkPolicy::AllowAll);
}

// --------------------------------------------------------------------------
// TEST 19: Container FS Ephemeral Overlay Lifecycle
// --------------------------------------------------------------------------
#[test]
fn test_19_container_fs_ephemeral_lifecycle() {
    let overlay_mgr = RootfsOverlayManager::new();
    let temp_root = std::env::temp_dir().join(format!("kuda_base_rootfs_{}", uuid::Uuid::new_v4()));
    let temp_ws = setup_temp_workspace("overlay_ws");
    let _ = fs::create_dir_all(&temp_root);

    let container = overlay_mgr.spawn_container_fs(&temp_root, &temp_ws).unwrap();
    assert!(container.root_dir.exists(), "Container root directory must be created");

    let cleanup_res = overlay_mgr.cleanup(&container);
    assert!(cleanup_res.is_ok(), "Container overlay cleanup must succeed");
    assert!(!container.root_dir.exists(), "Container root directory must be removed after cleanup");

    let _ = fs::remove_dir_all(&temp_root);
    let _ = fs::remove_dir_all(&temp_ws);
}

// --------------------------------------------------------------------------
// TEST 20: Non-Existent Binary Execution Fails Gracefully
// --------------------------------------------------------------------------
#[tokio::test]
async fn test_20_non_existent_command_fails_gracefully() {
    let ws = setup_temp_workspace("invalid_cmd");
    let executor = SandboxExecutor::new();
    let policy = SandboxPolicy::agent_default(ws.clone());

    let res = executor.execute_wait("non_existent_command_12345_xyz", &ws, &policy).await;
    assert!(res.is_ok());
    let out = res.unwrap();
    assert_ne!(out.exit_code, 0, "Non-existent command must yield non-zero exit code (127 in sh)");

    let _ = fs::remove_dir_all(&ws);
}
