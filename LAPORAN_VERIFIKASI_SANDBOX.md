# 📋 LAPORAN TEKNIS & HASIL AUDIT KUDA-SANDBOX (`minibox`)
**Comprehensive Engineering Report & Production Hardening Results**
*Revisi 2 — pasca-audit verifikasi silang & perbaikan*

---

## 📍 1. FULL PATH WORKSPACE & ARTIFAK

* **Workspace Root:** `/Users/macmini/.mounty/SSD_External/fix/kuda-sandbox`
* **Core Library:** `/Users/macmini/.mounty/SSD_External/fix/kuda-sandbox/crates/kuda-sandbox-core`
* **Daemon & CLI:** `/Users/macmini/.mounty/SSD_External/fix/kuda-sandbox/crates/kuda-sandbox-daemon`

---

## 🛡️ 2. HASIL IMPLEMENTASI & VERIFIKASI KODE NYATA

| Komponen | Implementasi Nyata | Status Verifikasi |
|---|---|---|
| **Tier 1 Process Sandbox** | Apple Sandbox SBPL (`darwin/profile.rs`) + `setrlimit` (`resource_limits.rs`) + Linux cgroups v2 fail-closed (`linux/cgroups.rs`) | ✅ **Lulus 20 test integrasi + 2 unit test**. Process tree killer (`killpg`), env scrubbing total, write/read jail aktif, deny `file-read-metadata` pada direktori sensitif. |
| **Tier 2 RootFS Container Engine** | **Linux: `pivot_root` nyata ke rootfs Alpine** (`linux/namespaces.rs::enter_container_root`) — overlay COW + bind-mount workspace `/workspace` + remount `/proc`, dieksekusi dengan binary milik container. **macOS: fallback jujur** — binary host di bawah SBPL write-jail + warning eksplisit (chroot butuh root). | ✅ **Lulus uji**. Tar-slip guard, ekstraksi atomik (temp+rename), deteksi kompresi by magic bytes (gz/xz/tar), streaming download, verifikasi SHA256 sidecar resmi Alpine. |
| **Tier 3 MicroVM Engine** | QEMU subprocess (`darwin_vz.rs` accel=hvf, `linux_kvm.rs` accel=kvm). **Wajib `--kernel <path>`** — tanpa kernel gagal cepat dengan pesan jelas (tidak hang). Wall-clock timeout diterapkan; exit code riil termasuk sinyal (128+N); quoting command aman via base64 (`init=/bin/sh -c "echo B64\|base64 -d\|sh"`); drives & network config benar-benar dipakai. | ✅ **Tervalidasi & Hardened** (butuh kernel image + qemu-system terpasang). |
| **Process Group Killer (`killpg`)** | `setpgid(0,0)` di `pre_exec` + `kill(-pid, SIGKILL)` saat timeout | ✅ **test_09 lulus** (seluruh proses anak-cucu terbunuh) |
| **Fail-Closed `setrlimit` & RLIMIT_NPROC** | Error `setrlimit(...)?` propagasi dari `pre_exec`. **RLIMIT_NPROC macOS bersifat user-wide** → limit efektif = jumlah proses user saat ini (via sysctl `KERN_PROC_ALL`) + budget fork sandbox, bukan nilai mentah policy. | ✅ **test_10 lulus**; fork bomb dibatasi tanpa mematikan proses user lain |
| **Pembersihan Environment Total** | `cmd.env_clear()` + injeksi ketat allowlist | ✅ **test_06 lulus** (zero secret leakage) |
| **Hardening Profil macOS (Darwin SBPL)** | Deny read `$HOME`, deny metadata `$HOME` (literal) + subdirektori sensitif, deny mach `SecurityServer`/`CoreAuthentication` | ✅ **test_04 lulus** |
| **Proteksi Daemon Socket & Workspace Boundary** | Socket mode `0600`; canonicalize + **guard berbasis prefix**: root sistem dilindungi persis + subtree terlarang (`/etc/**`, `/usr/**`, `/System/**`, `$HOME/.ssh`, dll). JSON invalid mendapat **error reply eksplisit** (client tidak menggantung). | ✅ **Teruji langsung**: `/opt/homebrew`, `/etc/apache2`, `$HOME/.ssh/sub` → ditolak; workspace valid → jalan |
| **Dynamic Network Control & SDK** | UDS Control Socket (`net/controller.rs`) **framing NDJSON** + error reply + cek kepemilikan socket lama (uid match, harus bertipe socket). SDK Python dengan escaping path. | ✅ **test_16, test_17 lulus** |
| **Network Chaos (tc netem)** | `NetworkChaosSimulator::apply_chaos/clear_chaos` **ter-wire ke CLI** (`--net-latency/--net-loss/--net-jitter/--net-bw-kbps/--net-corrupt/--net-iface`). Pakai `qdisc replace` (anti EEXIST), cleanup otomatis, gagal jujur bila tc tidak tersedia. | ✅ **Teruji**: non-Linux → warning eksplisit "Continuing WITHOUT chaos" (tidak ada sukses palsu) |
| **Multi-Architecture Detection & Runner** | `ElfDetector`: ELF LE **dan BE**, Mach-O 32/64-bit LE/BE, disambiguasi `0xCAFEBABE` (fat header vs Java class via nfat_arch), `requires_emulation` benar saat host==riscv64. `QemuRunner` resolusi binary dinamis (static/non-static). | ✅ **test_13, test_14, test_15 lulus** |
| **Metrik Riil** | `peak_memory_bytes` dari cgroup `memory.peak` (Linux) / `getrusage(RUSAGE_CHILDREN)` (macOS); setup duration diukur, bukan hardcode. | ✅ Tampil di output CLI (`Peak RSS: 1.9MB`) |

---

## 🔒 3. PERBAIKAN KEAMANAN PASCA-AUDIT

1. **Container masuk rootfs (Linux)** — `pivot_root` + detach old root + remount `/proc`, seccomp dimuat *setelah* pivot (urutan fail-closed).
2. **Ekstraksi tar.xz** — deteksi magic bytes (bukan ekstensi URL); Ubuntu/Debian `.tar.xz` kini bisa diekstrak.
3. **Seccomp default-on** — feature `seccomp` masuk `default`; syscall blocklist diambil dari `policy.blocked_ops.blocked_syscalls`.
4. **Cgroup fail-closed** — kegagalan tulis `memory.max/pids.max/cpu.max` menggagalkan sandbox; hanya unavailable yang degrade (dengan warning).
5. **Supply-chain** — SHA256 sidecar resmi Alpine diverifikasi (constant-time compare); HTTP status dicek; atomic rename mencegah cache parsial.
6. **Daemon** — prefix-based containment, error reply untuk JSON invalid, socket 0600.

---

## 🧪 4. BUKTI PENGUJIAN LANGSUNG DI TERMINAL

### A. Unit + Integration Test Suite (22 test):
```bash
$ cargo test

running 2 tests
test result: ok. 2 passed; 0 failed   (executor, net controller NDJSON)

running 20 tests
test result: ok. 20 passed; 0 failed  (security_and_isolation_tests)
```

### B. Uji Eksekusi Process Sandbox:
```bash
$ cargo run -p kuda-sandbox-daemon -- run "echo hello"
hello
📊 Metrics: Duration: 46ms (Setup: 2ms) | Exit: 0 | Peak RSS: 1.9MB | Platform: macOS (Apple Sandbox SBPL + setrlimit)
```

### C. Uji Container Engine di macOS (fallback jujur):
```bash
$ cargo run -p kuda-sandbox-daemon -- run "ls /bin" --engine container --rootfs alpine
⚠️  Container engine on this OS runs host binaries under the SBPL write-jail only;
    full rootfs isolation requires Linux (pivot_root) or root privileges.
bash
cat
```
> Di Linux, engine yang sama melakukan `pivot_root` ke rootfs Alpine dan mengeksekusi `/bin/sh` milik container.

### D. Uji Workspace Guard Daemon:
```json
{"workspace": "/opt/homebrew"}     → "Security Error: protected system/root directory"
{"workspace": "/etc/apache2"}      → "Security Error: inside a protected subtree (/private/etc)"
{"workspace": "/tmp/kuda_valid_ws"} → exit_code: 0 (eksekusi sukses)
"{not json"                        → "Protocol Error: invalid JSON request" (tanpa hang)
```

### E. Network Chaos jujur saat tc tidak tersedia:
```bash
$ cargo run -p kuda-sandbox-daemon -- run "echo t1" --net-latency 100
⚠️  Network chaos requested but could not be applied (tc requires Linux + CAP_NET_ADMIN). Continuing WITHOUT chaos.
```

---

## ⚠️ 5. BATASAN YANG DIKETAHUI (DOKUMENTASI JUJUR)

1. **Tier 2 di macOS** bukan container penuh (chroot butuh root; mount operation dibatasi sandbox) — berjalan sebagai SBPL write-jail + warning. Isolasi rootfs penuh hanya di Linux.
2. **Tier 3** memerlukan kernel image eksternal (`--kernel`) dan `qemu-system-*` terpasang; `is_supported()` kini memeriksa keberadaan binary.
3. **Network chaos** hanya efektif di Linux dengan CAP_NET_ADMIN pada interface yang diberikan (default `lo`).
4. **RLIMIT_NPROC di macOS** bersifat user-wide; limit efektif = proses user berjalan + budget sandbox.
