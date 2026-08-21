#[cfg(unix)]
use crate::error::Result;
#[cfg(not(unix))]
use crate::error::{Result, SandboxError};
use crate::policy::ResourcePolicy;

/// Applies POSIX resource limits (`setrlimit`) to the current process.
/// Must be invoked in the child process immediately after fork/pre_exec.
pub fn apply_setrlimit(policy: &ResourcePolicy) -> Result<()> {
    #[cfg(unix)]
    {
        use nix::sys::resource::{setrlimit, Resource};

        // RLIMIT_CPU: CPU execution time in seconds (SIGXCPU on soft limit, SIGKILL on hard limit)
        if policy.cpu_time_limit_secs > 0 {
            let cpu_limit = policy.cpu_time_limit_secs;
            setrlimit(Resource::RLIMIT_CPU, cpu_limit, cpu_limit + 5)?;
        }

        // Memory limit: On Linux enforce RLIMIT_AS. On macOS memory is isolated via Apple Sandbox virtual space / cgroups.
        #[cfg(target_os = "linux")]
        if policy.memory_limit_bytes > 0 {
            let mem_limit = policy.memory_limit_bytes;
            setrlimit(Resource::RLIMIT_AS, mem_limit, mem_limit)?;
        }

        // RLIMIT_FSIZE: Maximum writable file size in bytes
        if policy.max_file_size_bytes > 0 {
            let fsize = policy.max_file_size_bytes;
            setrlimit(Resource::RLIMIT_FSIZE, fsize, fsize)?;
        }

        // RLIMIT_NOFILE: Maximum open file descriptors
        if policy.max_open_files > 0 {
            let nofile = policy.max_open_files as u64;
            setrlimit(Resource::RLIMIT_NOFILE, nofile, nofile)?;
        }

        // RLIMIT_NPROC: Maximum number of processes/threads for current user (macOS & Linux)
        #[cfg(target_os = "linux")]
        if policy.max_pids > 0 {
            let nproc = policy.max_pids as u64;
            setrlimit(Resource::RLIMIT_NPROC, nproc, nproc)?;
        }

        // On macOS RLIMIT_NPROC is USER-WIDE (not per-sandbox). Setting it to
        // max_pids directly would break every process owned by this user.
        // Instead: allow all currently-running user processes + max_pids of
        // fork headroom for the sandbox itself.
        #[cfg(target_os = "macos")]
        if policy.max_pids > 0 {
            let effective = macos_effective_nproc(policy.max_pids as u64);
            let rlim = nix::libc::rlimit {
                rlim_cur: effective,
                rlim_max: effective,
            };
            unsafe {
                if nix::libc::setrlimit(nix::libc::RLIMIT_NPROC, &rlim) != 0 {
                    return Err(crate::error::SandboxError::SetupFailed("Failed to set RLIMIT_NPROC on macOS".into()));
                }
            }
        }

        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(SandboxError::Unsupported("POSIX setrlimit is not supported on this platform".into()))
    }
}

/// macOS: RLIMIT_NPROC is enforced per-user, so the effective limit must cover
/// every process the user already runs plus the sandbox's fork budget.
#[cfg(target_os = "macos")]
fn macos_effective_nproc(max_pids: u64) -> nix::libc::rlim_t {
    let current = user_process_count();
    current.saturating_add(max_pids).max(64)
}

#[cfg(target_os = "macos")]
fn user_process_count() -> u64 {
    use nix::libc;
    // sizeof(struct kinfo_proc) on Darwin is 648 bytes; libc crate does not
    // expose the struct on macOS, so query via a raw byte buffer.
    const KINFO_PROC_SIZE: usize = 648;

    unsafe {
        let mut name = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL];
        let mut size: libc::size_t = 0;

        if libc::sysctl(name.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) != 0 {
            return 0;
        }

        // Reserve headroom: process count can grow between the two sysctl calls
        let cap = size as usize / KINFO_PROC_SIZE + 64;
        let mut buf = vec![0u8; cap * KINFO_PROC_SIZE];
        size = buf.len() as libc::size_t;

        if libc::sysctl(name.as_mut_ptr(), 3, buf.as_mut_ptr() as *mut libc::c_void, &mut size, std::ptr::null_mut(), 0) != 0 {
            return 0;
        }

        (size as usize / KINFO_PROC_SIZE) as u64
    }
}
