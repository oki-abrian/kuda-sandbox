use crate::policy::{NetworkPolicy, SandboxPolicy};
use std::path::Path;

pub struct DarwinSandbox;

impl DarwinSandbox {
    /// Generates a valid Apple Sandbox Profile (SBPL) in Scheme format
    /// compatible with macOS `sandbox-exec -p <profile>`.
    pub fn generate_profile(policy: &SandboxPolicy) -> String {
        let mut sb = String::new();
        sb.push_str("(version 1)\n");
        sb.push_str("(allow default)\n\n");

        // 1. Jail all filesystem write operations (Deny write everywhere by default)
        sb.push_str("; === Strictly Deny All Writes by Default ===\n");
        sb.push_str("(deny file-write* (subpath \"/\"))\n\n");

        // 2. Deny reading entire $HOME directory by default to protect personal files, keys, browser cookies
        if let Ok(home) = std::env::var("HOME") {
            sb.push_str("; === Deny Reading Entire User Home Directory ===\n");
            sb.push_str(&format!("(deny file-read* (subpath \"{}\"))\n", home));
            // Metadata denial must stay narrow: denying metadata on ALL of $HOME
            // breaks getcwd()/ancestor lookups for legit paths under HOME.
            sb.push_str(&format!("(deny file-read-metadata (literal \"{}\"))\n", home));
        }

        // 3. Allow Write only to scratch/temp dirs and standard pseudo-devices
        sb.push_str("; === Allow Write to Temporary Dirs & Devices ===\n");
        sb.push_str("(allow file-write* (subpath \"/private/tmp\"))\n");
        sb.push_str("(allow file-write* (subpath \"/private/var/folders\"))\n");
        sb.push_str("(allow file-write* (subpath \"/tmp\"))\n");
        sb.push_str("(allow file-write* (subpath \"/dev/null\"))\n");
        sb.push_str("(allow file-write* (subpath \"/dev/zero\"))\n");
        sb.push_str("(allow file-write* (subpath \"/dev/dtracehelper\"))\n\n");

        // 4. Allow Read and Write strictly to configured workspace paths
        sb.push_str("; === Allow Read & Write Strictly to Workspace ===\n");
        for p in &policy.fs.rw_paths {
            sb.push_str(&format!("(allow file-read* file-write* (subpath \"{}\"))\n", p.display()));
            if let Ok(canon) = p.canonicalize() {
                if canon != *p {
                    sb.push_str(&format!("(allow file-read* file-write* (subpath \"{}\"))\n", canon.display()));
                }
            }
        }
        sb.push('\n');

        // 5. Allow Read-Only to system libraries, frameworks, interpreters, Homebrew
        sb.push_str("; === Allow Read to System Libraries & Interpreters ===\n");
        for p in &policy.fs.ro_paths {
            sb.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", p.display()));
        }
        sb.push_str("(allow file-read* (subpath \"/System\"))\n");
        sb.push_str("(allow file-read* (subpath \"/Library\"))\n");
        sb.push_str("(allow file-read* (subpath \"/usr\"))\n");
        sb.push_str("(allow file-read* (subpath \"/bin\"))\n");
        sb.push_str("(allow file-read* (subpath \"/sbin\"))\n");
        sb.push_str("(allow file-read* (subpath \"/opt/homebrew\"))\n\n");

        // 6. Strictly Deny Read and Write to sensitive credentials & keys
        sb.push_str("; === Explicit Sensitive Path & Key Denials ===\n");
        for p in &policy.fs.deny_paths {
            sb.push_str(&format!("(deny file-read* file-write* (subpath \"{}\"))\n", p.display()));
            // Block directory enumeration via stat/readdir metadata on secrets
            sb.push_str(&format!("(deny file-read-metadata (subpath \"{}\"))\n", p.display()));
            if let Ok(canon) = p.canonicalize() {
                if canon != *p {
                    sb.push_str(&format!("(deny file-read* file-write* (subpath \"{}\"))\n", canon.display()));
                    sb.push_str(&format!("(deny file-read-metadata (subpath \"{}\"))\n", canon.display()));
                }
            }
        }
        sb.push('\n');

        // 7. Network access isolation
        sb.push_str("; === Network Policy ===\n");
        match &policy.network {
            NetworkPolicy::Deny => {
                sb.push_str("(deny network*)\n");
            }
            NetworkPolicy::AllowAll => {
                sb.push_str("(allow network*)\n");
            }
            NetworkPolicy::AllowList(targets) => {
                // SBPL filters by IP, not hostname: resolve every target up-front
                // (in the trusted parent) and emit per-endpoint allow rules.
                let mut allowed_any = false;
                for t in targets {
                    let port = t.port;
                    let addrs = format!("{}:{}", t.host, port);
                    match std::net::ToSocketAddrs::to_socket_addrs(&addrs) {
                        Ok(iter) => {
                            for a in iter {
                                let rule = match (&a.ip(), &t.protocol) {
                                    (ip, crate::policy::NetProtocol::Udp) => {
                                        format!("(allow network-outbound (remote udp \"{}:{}\"))\n", ip, port)
                                    }
                                    (ip, _) => {
                                        format!("(allow network-outbound (remote tcp \"{}:{}\"))\n", ip, port)
                                    }
                                };
                                sb.push_str(&rule);
                                allowed_any = true;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("AllowList target '{}:{}' failed to resolve: {}", t.host, port, e);
                        }
                    }
                }
                if !allowed_any {
                    tracing::warn!("NetworkPolicy::AllowList resolved to zero endpoints; denying all network");
                }
                sb.push_str("(deny network*)\n");
            }
        }
        sb.push('\n');

        // 8. Block system administration, security daemon lookup & kernel privileges
        sb.push_str("; === Blocked Privileged & Security Services ===\n");
        sb.push_str("(deny sysctl-write)\n");
        sb.push_str("(deny system-privilege)\n");
        sb.push_str("(deny mach-lookup (global-name \"com.apple.SecurityServer\"))\n");
        sb.push_str("(deny mach-lookup (global-name \"com.apple.CoreAuthentication.daemon\"))\n");
        for rule in &policy.blocked_ops.darwin_deny_rules {
            sb.push_str(&format!("{}\n", rule));
        }

        sb
    }

    /// Wraps a command into `sandbox-exec -p "<profile>" <command>`
    pub fn build_command(
        policy: &SandboxPolicy,
        command_str: &str,
        working_dir: &Path,
    ) -> tokio::process::Command {
        let profile = Self::generate_profile(policy);
        let mut cmd = tokio::process::Command::new("/usr/bin/sandbox-exec");
        cmd.arg("-p")
            .arg(profile)
            .arg("/bin/sh")
            .arg("-c")
            .arg(command_str);

        cmd.current_dir(working_dir);
        cmd
    }
}
