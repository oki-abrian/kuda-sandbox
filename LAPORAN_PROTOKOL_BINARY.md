# 📡 LAPORAN IMPLEMENTASI: BINARY WIRE PROTOCOL + FD PASSING
**Pengganti Protokol JSON Teks pada kuda-sandbox (`minibox`)**
*Untuk diverifikasi silang oleh reviewer/AI lain — semua klaim disertai lokasi kode & perintah reproduksi.*

---

## 1. RINGKASAN ARSITEKTUR

Implementasi mengikuti opsi **#1 (Binary Framing) + #2 (SCM_RIGHTS)** dari proposal. Opsi #3 (gRPC/tonic) **sengaja tidak dipakai**: menambah deps berat (prost/tonic) + kebutuhan `protoc` untuk proyek sekecil ini; multi-bahasa tetap tercapai lewat SDK generator.

### Format Frame (little-endian, 13-byte header)
```
┌──────────────┬────────────┬───────────────┬─────────────────────────┐
│ Magic 4B     │ Type 1B    │ Length 8B u64 │ Payload                 │
│ "KUDA"       │ MsgType    │ LE            │ raw binary / JSON UTF-8 │
└──────────────┴────────────┴───────────────┴─────────────────────────┘
```

### Keputusan desain yang sudah DIKONFIRMASI user
- **Payload terstruktur = JSON di dalam frame** (bukan bincode): `ExecRequest`, `ExitStatus`. Alasan: self-describing, SDK Python/Go/Node tidak perlu decoder manual, ukuran pesan kontrol <300B sehingga selisih parse tak signifikan.
- **Data bulk = raw binary tanpa base64**: chunk stdout/stderr (64KB per chunk), streaming live selama proses jalan.
- **File besar = zero-copy via SCM_RIGHTS**: fd dup antar-proses, byte tidak pernah melewati socket.

### Tipe Pesan (`net/wire.rs::MsgType`)
| Byte | Nama | Payload | Keterangan |
|---|---|---|---|
| 0x01 | ExecRequest | JSON | boleh membawa fd (stdin child) via SCM_RIGHTS |
| 0x02 | StdoutChunk | raw | streaming live |
| 0x03 | StderrChunk | raw | streaming live |
| 0x04 | Exit | JSON | exit_code + ExecutionMetrics |
| 0x05 | Error | UTF-8 | guard/security/runtime error |
| 0x06 | FileGetRequest | path / u64-size | request & reply (reply bawa fd) |
| 0x07 | FileEof | kosong | terminator FILE_GET |

---

## 2. FILE YANG DIUBAH/DIBUAT

| File | Perubahan |
|---|---|
| `crates/kuda-sandbox-core/src/net/wire.rs` | **BARU ~550 baris**: codec frame, recvmsg loop, server RPC (`serve_connection`, `handle_exec`, `handle_file_get`), client (`BinaryClient`), `classify_workspace` (dipindah dari main.rs) |
| `crates/kuda-sandbox-core/src/executor.rs` | Refactor: `build_command()` diekstrak; **BARU** `execute_wait_streaming_with_stdin()` (chunk callback via mpsc + stdin Stdio opsional); `execute_wait` kini wrapper collector; unit test streaming |
| `crates/kuda-sandbox-core/src/net/mod.rs`, `lib.rs` | export modul wire |
| `crates/kuda-sandbox-daemon/src/main.rs` | Subcommand `Daemon` → binary protocol; **BARU subcommand client `Exec`** dengan `--stdin-file`, `--fetch remote:local`; hapus loop JSON lama |
| `crates/kuda-sandbox-core/src/net/sdk.rs` | SDK Python regenerasi: `SandboxClient` (binary framing + fd passing, struct pack/unpack) + `NetworkController` (tetap NDJSON — pesan kontrol chaos kecil, sengaja) |
| `crates/kuda-sandbox-core/Cargo.toml` | nix feature `socket`; dep `bincode` (akhirnya tak terpakai — bisa dihapus) |
| `tests/binary_protocol_tests.rs` | **BARU 7 test** |

---

## 3. BUG KRITIS YANG DITEMUKAN & DIPERBAIKI SAAT SESI INI

Dokumentasi lengkap karena ini pelajaran teknis yang memvalidasi implementasi:

### Bug A — "13-byte phantom header" (deadlock total)
Di versi awal `recv_frame`: header 13B dibaca via tokio `read_exact`, lalu jalur-fd menghitung `total = HEADER_LEN + len` padahal header sudah termakan → penerima menunggu 13 byte yang tak pernah dikirim. Gejala: semua frame ExecRequest/FileGet menggantung (`filled=123/136`). **Fix**: hitung payload saja.

### Bug B — SCM_RIGHTS hilang jika header dibaca `read_exact`
Pada `SOCK_STREAM`, ancillary data menempel pada **byte pertama** transmisi sendmsg. Membaca header pakai `read_exact` biasa = cmsg terbuang diam-diam (`cmsgs=0`, "daemon did not attach an fd"). **Fix arsitektural**: SATU jalur pembacaan seragam — semua frame dibaca dari byte pertama lewat loop `recvmsg` (header diparse begitu ≥13B terkumpul, lalu lanjut sampai `HEADER_LEN+len`). Loop tidak perleh over-read (`recvmsg(want)` dibatasi sisa need) sehingga frame tetap terpisah.

### Bug C — Busy-spin readiness tokio (regresi saat fix Bug B)
Raw `nix::recvmsg` TIDAK membersihkan cached-readiness tokio. Setelah frame pertama, `readable().await` berikutnya langsung "Ready" palsu → `recvmsg` EAGAIN → spin tak berujung di runtime single-thread (`#[tokio::test]`) → deadlock seluruh task. **Fix**: bungkus recvmsg dalam `stream.try_io(Interest::READABLE, ...)` — kontrak resmi tokio agar WouldBlock memicu `clear_ready`.

### Bug D — Path canonicalization mismatch
Workspace disimpan non-kanonik (`/var/folders/...`) tapi FILE_GET membandingkan hasil `canonicalize()` (`/private/var/folders/...`) → penolakan false-positive. **Fix**: kanonikalkan workspace sebelum disimpan sebagai session state.

### Penguatan keamanan yang muncul dari review sendiri
- `FILE_GET` kini **terkunci ke workspace sesi yang sama** (`serve_connection` menyimpan `session_workspace`; path di luar → Error frame). Sebelumnya hanya dicek "bukan path terlarang" = bisa eksfiltrasi file `$HOME` sembarang.

---

## 4. BUKTI VERIFIKASI (reproducible)

### A. Test suite — 30/30 hijau, 0 warning
```bash
$ cargo test
running 3 tests   (lib: executor echo, streaming chunks, net controller NDJSON)
test result: ok. 3 passed
running 7 tests   (binary_protocol_tests)
test result: ok. 7 passed
running 20 tests  (security_and_isolation_tests)
test result: ok. 20 passed
```
`$ cargo build 2>&1 | grep -c warning` → **0**

Isi `binary_protocol_tests.rs` (semua lulus):
1. roundtrip frame dua arah + payload 300KB
2. tolak magic salah & length > MAX_FRAME_LEN (16 MiB) → SecurityViolation
3. exec streaming: stdout/stderr tiba sebagai chunk SEBELUM Exit frame; metrik riil
4. **fd stdin zero-copy**: file ~96KB dikirim sebagai descriptor; `cat` membaca persis sama
5. **FILE_GET fd handoff**: artifact dibuat di sandbox, diterima lokal utuh; path luar workspace DITOLAK; koneksi tanpa exec DITOLAK
6. guard workspace `/opt/homebrew` di jalur wire → Error frame
7. aturan classify_workspace

### B. End-to-end CLI (dua proses nyata, daemon + client)
```bash
$ kuda-sandbox-daemon daemon --socket /tmp/kw_e2e.sock &
$ kuda-sandbox-daemon exec "cat; echo STREAM-OK" \
    --socket /tmp/kw_e2e.sock --workspace /tmp/kw_ws --stdin-file /tmp/kw_input.txt
STREAM-OK                      ← isi /tmp/kw_input.txt masuk via fd (tanpa copy socket)
📊 Remote Metrics: Duration: 36ms | Exit: 0 | Peak RSS: 1.9MB

$ kuda-sandbox-daemon exec "printf 'artifact...' > result.txt" --workspace /tmp/kw_ws ...
$ kuda-sandbox-daemon exec "true" --workspace /tmp/kw_ws \
    --fetch "/tmp/kw_ws/result.txt:/tmp/kw_local_result.txt"
📥 Fetched '/tmp/kw_ws/result.txt' -> local (23 bytes, FD handoff)
artifact-E2E-1787308685        ← isi cocok
```

---

## 5. BATASAN & CATATAN JUJUR UNTUK REVIEWER

1. **`bincode` di Cargo.toml tidak lagi dipakai** (payload kontrol memakai JSON sesi kesepakatan) — aman dihapus.
2. **FD stdin hanya diduplikasi, offset file dibagi** dengan proses client (semantik dup). Untuk multi-use file, client perlu buka ulang per request.
3. `MAX_FRAME_LEN = 16 MiB` — stdout chunk otomatis dipecah 64KB; file besar tidak pernah melewati frame (via fd), jadi cap aman.
4. **Belum ada TLS/auth pada UDS** — model ancaman tetap "user lokal sama" (socket 0600); sama seperti sebelumnya, bukan regresi.
5. Windows tidak didukung (SCM_RIGHTS = POSIX).
6. `handle_file_get` melakukan `canonicalize` + prefix-check — ada TOCTOU teoretis rename antara cek dan open; mitigasi natural: workspace milik user yang sama & sandbox write-jail. Disarankan follow-up: `openat2(REQUIRE_INODE)` di Linux.
7. SDK Python `fetch_file` membaca sisa buffer pertama dari `payload[8:]` — benar untuk reply 21B; jika nanti payload FileGetRequest-reply diperluas, perlu loop baca tambahan.
8. Controller network-chaos **tetap NDJSON** — pesan kontrolnya kecil dan sudah punya test; migrasi ke binary tidak bernilai sekarang.

## 6. PERINTAH REPRODUKSI CEPAT
```bash
cd /Users/macmini/.mounty/SSD_External/fix/kuda-sandbox
cargo test                                   # 30 passed, 0 warnings
cargo run -p kuda-sandbox-daemon -- daemon --socket /tmp/k.sock &
cargo run -p kuda-sandbox-daemon -- exec "echo hi" --socket /tmp/k.sock --workspace /tmp
```
