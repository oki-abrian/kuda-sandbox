use clap::{Parser, Subcommand};
use kuda_sandbox_core::arch::ElfDetector;
use kuda_sandbox_core::policy::NetworkPolicy;
use kuda_sandbox_core::rootfs::ImageManager;
use kuda_sandbox_core::{QemuRunner, SandboxExecutor, SandboxPolicy};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "minibox")]
#[command(about = "Sub-50ms Isolated Code Execution & MicroVM Engine for AI Agents in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute a command in an isolated sandbox (process, rootfs container, or microvm)
    Run {
        /// The shell command string to run
        command: String,

        /// Workspace directory to mount read-write (defaults to current dir)
        #[arg(short, long)]
        workspace: Option<PathBuf>,

        /// Execution engine: process (fastest), container (OCI rootfs), microvm (full kernel)
        #[arg(long, default_value = "process")]
        engine: String,

        /// Target rootfs distribution (alpine, ubuntu, debian)
        #[arg(long)]
        rootfs: Option<String>,

        /// Target CPU architecture (x86_64, aarch64, riscv64)
        #[arg(long)]
        arch: Option<String>,

        /// Enable outbound network access (default: false)
        #[arg(long, default_value_t = false)]
        allow_net: bool,

        /// Injected network latency in milliseconds for chaos resilience test
        #[arg(long, default_value_t = 0)]
        net_latency: u64,

        /// Injected packet loss percentage (e.g. 5 for 5%)
        #[arg(long, default_value_t = 0.0)]
        net_loss: f32,

        /// Injected jitter in milliseconds (Linux tc netem only)
        #[arg(long, default_value_t = 0)]
        net_jitter: u64,

        /// Bandwidth throttle in Kbps (Linux tc netem only)
        #[arg(long)]
        net_bw_kbps: Option<u64>,

        /// Corrupted packet ratio percentage (Linux tc netem only)
        #[arg(long, default_value_t = 0.0)]
        net_corrupt: f32,

        /// Network interface for tc netem chaos (default: lo, safe inside sandbox netns)
        #[arg(long, default_value = "lo")]
        net_iface: String,

        /// Linux kernel image for the microvm engine (required for engine=microvm)
        #[arg(long)]
        kernel: Option<PathBuf>,

        /// Optional initrd for the microvm engine
        #[arg(long)]
        initrd: Option<PathBuf>,

        /// Memory limit in Megabytes (default: 512 MB)
        #[arg(long, default_value_t = 512)]
        ram_mb: u64,

        /// Timeout in seconds (default: 60s)
        #[arg(short, long, default_value_t = 60)]
        timeout: u64,
    },

    /// Inspect an executable ELF binary architecture and emulation requirement
    Arch {
        /// Path to the binary file
        path: PathBuf,
    },

    /// Show current host OS isolation primitives & virtualization capabilities
    Info,

    /// Manage rootfs container images
    Image {
        #[command(subcommand)]
        sub: ImageCommands,
    },

    /// Start a Unix Domain Socket Daemon speaking the kuda binary wire protocol
    /// (length-prefixed frames, streamed output, SCM_RIGHTS fd passing)
    Daemon {
        /// Socket path (default: /tmp/kuda_sandbox.sock)
        #[arg(short, long, default_value = "/tmp/kuda_sandbox.sock")]
        socket: PathBuf,
    },

    /// Client: execute a command on a running kuda daemon via the binary protocol.
    /// Output is streamed live; large stdin/artifacts travel as passed FDs (zero-copy).
    Exec {
        /// The shell command string to run remotely
        command: String,

        /// Daemon socket path
        #[arg(short, long, default_value = "/tmp/kuda_sandbox.sock")]
        socket: PathBuf,

        /// Workspace directory to mount read-write (defaults to current dir)
        #[arg(long)]
        workspace: Option<PathBuf>,

        /// Enable outbound network access (default: false)
        #[arg(long, default_value_t = false)]
        allow_net: bool,

        /// Memory limit in Megabytes (default: 512 MB)
        #[arg(long, default_value_t = 512)]
        ram_mb: u64,

        /// Timeout in seconds (default: 60s)
        #[arg(short, long, default_value_t = 60)]
        timeout: u64,

        /// Local file whose descriptor is handed to the remote child as stdin (zero-copy)
        #[arg(long)]
        stdin_file: Option<PathBuf>,

        /// After execution, fetch a workspace file via FD handoff: --fetch <remote-path>:<local-dest>
        #[arg(long)]
        fetch: Option<String>,
    },
}

#[derive(Subcommand)]
enum ImageCommands {
    /// List cached rootfs distributions
    List,
    /// Pull an official rootfs distribution from cloud registry
    Pull {
        /// Distribution name (alpine, ubuntu, debian)
        #[arg(default_value = "alpine")]
        distro: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .compact()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            command,
            workspace,
            engine,
            rootfs,
            arch,
            allow_net,
            net_latency,
            net_loss,
            net_jitter,
            net_bw_kbps,
            net_corrupt,
            net_iface,
            kernel,
            initrd,
            ram_mb,
            timeout,
        } => {
            let ws = workspace.unwrap_or_else(|| std::env::current_dir().unwrap());
            let mut policy = SandboxPolicy::agent_default(ws.clone());
            policy.resources.memory_limit_bytes = ram_mb * 1024 * 1024;
            policy.resources.wall_time_limit_secs = timeout;
            if allow_net {
                policy.network = NetworkPolicy::AllowAll;
            }

            let target_arch = arch.as_deref().map(|a| match a {
                "x86_64" | "amd64" => kuda_sandbox_core::Architecture::X86_64,
                "aarch64" | "arm64" => kuda_sandbox_core::Architecture::Aarch64,
                "riscv64" => kuda_sandbox_core::Architecture::Riscv64,
                other => {
                    eprintln!("❌ Unknown --arch '{}'. Valid: x86_64, aarch64, riscv64", other);
                    std::process::exit(2);
                }
            });

            // Wrap with QEMU if cross-arch is requested
            let effective_cmd = QemuRunner::wrap_if_needed(&command, target_arch);

            // Validate engine up-front — no silent fallback to 'process'
            let engine_name = engine.to_lowercase();
            if !matches!(engine_name.as_str(), "process" | "container" | "microvm") {
                eprintln!("❌ Unknown --engine '{}'. Valid: process, container, microvm", engine);
                std::process::exit(2);
            }

            println!("🚀 Executing in kuda-sandbox [Engine: {}]...", engine);
            #[cfg(target_os = "macos")]
            let ram_note = " (advisory on macOS; enforced via cgroups/RLIMIT_AS on Linux)";
            #[cfg(not(target_os = "macos"))]
            let ram_note = "";
            println!("🔒 Policy: RAM={}MB{} | Timeout={}s | Net={:?}", ram_mb, ram_note, timeout, policy.network);

            // Wire network chaos into the real tc netem qdisc (Linux only).
            let chaos_profile = kuda_sandbox_core::ChaosProfile {
                latency_ms: net_latency,
                jitter_ms: net_jitter,
                packet_loss: net_loss / 100.0,
                bandwidth_kbps: net_bw_kbps,
                corrupt_ratio: net_corrupt / 100.0,
            };
            let chaos_applied = chaos_profile.is_active()
                && kuda_sandbox_core::NetworkChaosSimulator::apply_chaos(&chaos_profile, &net_iface).is_ok();
            if chaos_profile.is_active() && !chaos_applied {
                eprintln!("⚠️  Network chaos requested but could not be applied (tc requires Linux + CAP_NET_ADMIN). Continuing WITHOUT chaos.");
            } else if chaos_applied {
                println!("🌐 Network Chaos Active on '{}': +{}ms latency (±{}ms) | {:.1}% loss", net_iface, net_latency, net_jitter, net_loss);
            }

            let executor = SandboxExecutor::new();
            let rootfs_str = rootfs.as_deref().unwrap_or("alpine");
            let rootfs_image = match rootfs_str.to_lowercase().as_str() {
                "alpine" => kuda_sandbox_core::RootfsImage::Alpine,
                "ubuntu" => kuda_sandbox_core::RootfsImage::Ubuntu,
                "debian" => kuda_sandbox_core::RootfsImage::Debian,
                custom => kuda_sandbox_core::RootfsImage::Custom(custom.to_string()),
            };

            let run_res = match engine_name.as_str() {
                "container" => executor.execute_container(&effective_cmd, &ws, &rootfs_image, &policy).await,
                "microvm" => {
                    if kernel.is_none() {
                        eprintln!("❌ Engine 'microvm' requires --kernel <path-to-vmlinux|bzImage>. Without a kernel the VM cannot boot.");
                        cleanup_chaos(&chaos_profile, &net_iface, chaos_applied);
                        std::process::exit(2);
                    }
                    let vm_cfg = kuda_sandbox_core::VmConfig {
                        vcpu_count: 2,
                        ram_mb,
                        kernel_path: kernel.clone(),
                        initrd_path: initrd.clone(),
                        boot_args: String::new(),
                        drives: vec![],
                        network: kuda_sandbox_core::VmNetwork::None,
                        timeout_secs: timeout.max(60),
                    };
                    executor.execute_microvm(&effective_cmd, &vm_cfg).await
                }
                _ => executor.execute_wait(&effective_cmd, &ws, &policy).await,
            };

            if chaos_applied {
                cleanup_chaos(&chaos_profile, &net_iface, true);
            }

            let res = match run_res {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("❌ Sandbox error: {}", e);
                    flush_stdio();
                    std::process::exit(1);
                }
            };

            if !res.stdout.is_empty() {
                print!("{}", res.stdout);
            }
            if !res.stderr.is_empty() {
                eprint!("{}", res.stderr);
            }

            println!("\n📊 Metrics: Duration: {}ms (Setup: {}ms) | Exit: {} | Peak RSS: {} | Platform: {}",
                res.metrics.execution_duration_ms,
                res.metrics.setup_duration_ms,
                res.exit_code,
                format_bytes(res.metrics.peak_memory_bytes),
                res.metrics.platform
            );

            flush_stdio();
            std::process::exit(res.exit_code);
        }

        Commands::Arch { path } => {
            let detected = ElfDetector::detect_binary_architecture(&path)?;
            let host = ElfDetector::host_architecture();
            let needs_emu = ElfDetector::requires_emulation(&path);

            println!("=== Binary Architecture Analysis ===");
            println!("File: {}", path.display());
            println!("Detected Architecture: {:?}", detected);
            println!("Host Architecture: {:?}", host);
            println!("Requires CPU Emulation: {}", if needs_emu { "YES (QEMU/Rosetta)" } else { "NO (Native)" });
        }

        Commands::Info => {
            println!("=== Kuda Sandbox Multi-Tier Capabilities ===");
            println!("Tier 1 (Process Sandbox): ACTIVE (< 30ms)");
            println!("Tier 2 (Rootfs Container): ACTIVE (OverlayFS + OCI images)");
            #[cfg(target_os = "macos")]
            {
                println!("Tier 3 (MicroVM Virtualization): Apple Silicon Hypervisor (Virtualization.framework)");
                println!("Host OS: macOS (Darwin)");
                println!("Multi-Arch: Rosetta 2 + QEMU User Emulation");
            }
            #[cfg(target_os = "linux")]
            {
                println!("Tier 3 (MicroVM Virtualization): Linux KVM (/dev/kvm)");
                println!("Host OS: Linux");
                println!("Multi-Arch: binfmt_misc + QEMU static");
            }
        }

        Commands::Image { sub } => match sub {
            ImageCommands::List => {
                let img_mgr = ImageManager::new();
                println!("=== Cached Rootfs Distributions ===");
                println!("Alpine Linux (3.20): {}", if img_mgr.is_cached(&kuda_sandbox_core::RootfsImage::Alpine) { "CACHED" } else { "AVAILABLE (Auto-pull on demand)" });
                println!("Ubuntu Minimal (24.04): {}", if img_mgr.is_cached(&kuda_sandbox_core::RootfsImage::Ubuntu) { "CACHED" } else { "AVAILABLE (Auto-pull on demand)" });
                println!("Debian Slim (12): {}", if img_mgr.is_cached(&kuda_sandbox_core::RootfsImage::Debian) { "CACHED" } else { "AVAILABLE (Auto-pull on demand)" });
            }
            ImageCommands::Pull { distro } => {
                let img_mgr = ImageManager::new();
                let image = match distro.to_lowercase().as_str() {
                    "alpine" => kuda_sandbox_core::RootfsImage::Alpine,
                    "ubuntu" => kuda_sandbox_core::RootfsImage::Ubuntu,
                    "debian" => kuda_sandbox_core::RootfsImage::Debian,
                    custom => kuda_sandbox_core::RootfsImage::Custom(custom.to_string()),
                };
                println!("⬇️  Pulling official rootfs image for '{}'...", distro);
                match img_mgr.pull_image(&image).await {
                    Ok(path) => {
                        println!("✅ Successfully pulled and unpacked rootfs to: {}", path.display());
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to pull image: {}", e);
                    }
                }
            }
        },

        Commands::Daemon { socket } => {
            println!("⚡ Starting kuda-sandbox daemon (binary wire protocol) on {}", socket.display());
            if socket.exists() {
                let _ = std::fs::remove_file(&socket);
            }
            let listener = tokio::net::UnixListener::bind(&socket)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
            }
            println!("✅ Daemon ready. Magic='KUDA' | streamed output | SCM_RIGHTS fd passing | Socket 0600");

            let executor = SandboxExecutor::new();

            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let exec = executor.clone();
                    tokio::spawn(async move {
                        kuda_sandbox_core::wire::serve_connection(&exec, stream).await;
                    });
                }
            }
        }

        Commands::Exec {
            command,
            socket,
            workspace,
            allow_net,
            ram_mb,
            timeout,
            stdin_file,
            fetch,
        } => {
            let ws = workspace.unwrap_or_else(|| std::env::current_dir().unwrap());
            let ws_canon = ws.canonicalize().map_err(|e| {
                anyhow::anyhow!("Workspace '{}' is invalid: {}", ws.display(), e)
            })?;
            if let Err(reason) = kuda_sandbox_core::wire::classify_workspace(&ws_canon) {
                anyhow::bail!("{}", reason);
            }

            let mut client = kuda_sandbox_core::BinaryClient::connect(&socket).await?;

            let req = kuda_sandbox_core::ExecRequest {
                command: command.clone(),
                workspace: ws_canon.to_string_lossy().to_string(),
                allow_net,
                ram_mb,
                timeout_secs: timeout,
                stdin_from_fd: stdin_file.is_some(),
            };

            use std::io::Write as _;
            let exit_code = {
                let mut code: i32 = -1;
                client
                    .exec(&req, stdin_file.as_deref(), |ev| match ev {
                        kuda_sandbox_core::ExecEvent::Stdout(chunk) => {
                            let _ = std::io::stdout().write_all(&chunk);
                            let _ = std::io::stdout().flush();
                        }
                        kuda_sandbox_core::ExecEvent::Stderr(chunk) => {
                            let _ = std::io::stderr().write_all(&chunk);
                            let _ = std::io::stderr().flush();
                        }
                        kuda_sandbox_core::ExecEvent::Exit(st) => {
                            code = st.exit_code;
                            eprintln!(
                                "\n📊 Remote Metrics: Duration: {}ms (Setup: {}ms) | Exit: {} | Peak RSS: {} | Platform: {}",
                                st.metrics.execution_duration_ms,
                                st.metrics.setup_duration_ms,
                                st.exit_code,
                                format_bytes(st.metrics.peak_memory_bytes),
                                st.metrics.platform
                            );
                        }
                        kuda_sandbox_core::ExecEvent::Error(msg) => {
                            eprintln!("❌ Daemon error: {}", msg);
                            code = 1;
                        }
                    })
                    .await?;
                code
            };

            if let Some(spec) = fetch {
                let (remote, local) = spec.split_once(':').unwrap_or((spec.as_str(), "fetched_file"));
                let written = client.fetch_file(remote, std::path::Path::new(local)).await?;
                eprintln!("📥 Fetched '{}' -> '{}' ({} bytes, FD handoff)", remote, local, written);
            }

            flush_stdio();
            std::process::exit(exit_code);
        }
    }

    Ok(())
}

fn cleanup_chaos(profile: &kuda_sandbox_core::ChaosProfile, iface: &str, applied: bool) {
    if profile.is_active() && applied {
        if let Err(e) = kuda_sandbox_core::NetworkChaosSimulator::clear_chaos(iface) {
            eprintln!("⚠️  Failed to clean up tc netem on '{}': {}", iface, e);
        }
    }
}

fn flush_stdio() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
}

fn format_bytes(b: u64) -> String {
    if b >= 1024 * 1024 {
        format!("{:.1}MB", b as f64 / (1024.0 * 1024.0))
    } else if b >= 1024 {
        format!("{:.1}KB", b as f64 / 1024.0)
    } else {
        format!("{}B", b)
    }
}
