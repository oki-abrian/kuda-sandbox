use crate::error::Result;
use std::fs;
use std::path::Path;

pub struct PythonSdkGenerator;

impl PythonSdkGenerator {
    /// Generates the standalone `kuda_sandbox.py` SDK file in the workspace.
    /// Contains:
    /// - SandboxClient: kuda binary wire protocol (frames + SCM_RIGHTS fd passing)
    /// - NetworkController: NDJSON control socket for runtime network chaos
    pub fn write_python_sdk(workspace: &Path, socket_path: &Path) -> Result<()> {
        let sdk_file = workspace.join("kuda_sandbox.py");
        let escaped_path = socket_path.display().to_string().replace('\\', "\\\\").replace('"', "\\\"");
        let content = format!(r#"# Kuda Sandbox SDK
# Generated automatically by Kuda Sandbox Engine
#
# - SandboxClient     : binary wire protocol ("KUDA" frames, streamed raw output,
#                       zero-copy stdin/artifact transfer via SCM_RIGHTS fd passing).
#                       Structured payloads (ExecRequest/ExitStatus) are UTF-8 JSON.
# - NetworkController : NDJSON control socket for live network chaos mutation.

import os
import sys
import json
import struct
import array
import socket

DEFAULT_SOCKET_PATH = "{socket}"
MAGIC = b"KUDA"
HEADER = struct.Struct("<4sBQ")

# Message types (must match crates/kuda-sandbox-core/src/net/wire.rs)
T_EXEC_REQUEST = 0x01
T_STDOUT = 0x02
T_STDERR = 0x03
T_EXIT = 0x04
T_ERROR = 0x05
T_FILE_GET = 0x06
T_FILE_EOF = 0x07


class SandboxError(RuntimeError):
    pass


class ProtocolError(RuntimeError):
    pass


class SandboxClient:
    """High-throughput client for the kuda-sandbox daemon (binary wire protocol)."""

    def __init__(self, socket_path=DEFAULT_SOCKET_PATH):
        self.socket_path = socket_path

    # ---- low-level framing -------------------------------------------------
    @staticmethod
    def _pack_frame(msg_type, payload=b""):
        return HEADER.pack(MAGIC, msg_type, len(payload)) + payload

    @staticmethod
    def _recv_exact(sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("daemon closed mid-frame")
            buf += chunk
        return buf

    def _send_frame(self, sock, msg_type, payload=b"", fd=None):
        data = self._pack_frame(msg_type, payload)
        if fd is None:
            sock.sendall(data)
        else:
            # Ancillary data rides on ONE sendmsg; remainder (if any) as plain bytes
            fds = array.array("i", [fd])
            sent = sock.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds.tobytes())])
            if sent < len(data):
                sock.sendall(data[sent:])

    def _recv_frame(self, sock):
        header = self._recv_exact(sock, HEADER.size)
        magic, msg_type, length = HEADER.unpack(header)
        if magic != MAGIC:
            raise ProtocolError("bad wire magic %r" % magic)
        return msg_type, self._recv_exact(sock, length)

    def _recv_fd_frame(self, sock):
        """Reads one full frame that may carry an SCM_RIGHTS descriptor.
        The ancillary data arrives attached to the first recvmsg chunk."""
        buf = b""
        fd = None
        need = HEADER.size
        while True:
            want = max(1, need - len(buf))
            data, ancdata, _, _ = sock.recvmsg(want)
            if not data and not ancdata:
                raise ConnectionError("daemon closed mid-frame")
            if fd is None:
                for level, ctype, cdata in ancdata:
                    if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
                        fd = struct.unpack("i", cdata[:array.array("i").itemsize])[0]
            buf += data
            if len(buf) >= HEADER.size and need == HEADER.size:
                need = HEADER.size + HEADER.unpack(buf[:HEADER.size])[2]
            if len(buf) >= need:
                break
        magic, msg_type, length = HEADER.unpack(buf[:HEADER.size])
        if magic != MAGIC:
            raise ProtocolError("bad wire magic %r" % magic)
        return msg_type, buf[HEADER.size:need], fd

    # ---- high-level API ----------------------------------------------------
    def exec(self, command, workspace=".", allow_net=False, ram_mb=512,
             timeout_secs=60, stdin_file=None):
        """Run `command` in the sandbox. Streams stdout/stderr live to this
        process. Returns (exit_code, metrics_dict).

        stdin_file: local file handed to the remote child as stdin via an
        SCM_RIGHTS descriptor pass — no byte copying through the socket.
        """
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket_path)
        try:
            req = json.dumps({{
                "command": command,
                "workspace": workspace,
                "allow_net": allow_net,
                "ram_mb": ram_mb,
                "timeout_secs": timeout_secs,
                "stdin_from_fd": bool(stdin_file),
            }}).encode()

            if stdin_file is not None:
                fd = os.open(stdin_file, os.O_RDONLY)
                try:
                    self._send_frame(sock, T_EXEC_REQUEST, req, fd=fd)
                finally:
                    os.close(fd)
            else:
                self._send_frame(sock, T_EXEC_REQUEST, req)

            while True:
                mtype, payload = self._recv_frame(sock)
                if mtype == T_STDOUT:
                    sys.stdout.buffer.write(payload)
                    sys.stdout.buffer.flush()
                elif mtype == T_STDERR:
                    sys.stderr.buffer.write(payload)
                    sys.stderr.buffer.flush()
                elif mtype == T_EXIT:
                    st = json.loads(payload.decode())
                    return st["exit_code"], st["metrics"]
                elif mtype == T_ERROR:
                    raise SandboxError(payload.decode())
                else:
                    raise ProtocolError("unexpected frame type 0x%02x" % mtype)
        finally:
            sock.close()

    def fetch_file(self, remote_path, dest_path):
        """Zero-copy artifact retrieval: daemon passes an open FD over the
        socket; we read straight from it into dest_path."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket_path)
        try:
            self._send_frame(sock, T_FILE_GET, remote_path.encode())

            mtype, payload, fd = self._recv_fd_frame(sock)
            if mtype == T_ERROR:
                raise SandboxError(payload.decode())
            if mtype != T_FILE_GET or fd is None or len(payload) < 8:
                raise ProtocolError("bad FILE_GET reply")

            expected = struct.unpack("<Q", payload[:8])[0]
            leftover = payload[8:]
            with os.fdopen(fd, "rb") as src, open(dest_path, "wb") as out:
                out.write(leftover)
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)

            mtype2, _ = self._recv_frame(sock)
            if mtype2 != T_FILE_EOF:
                raise ProtocolError("missing EOF marker after FILE_GET")

            written = os.path.getsize(dest_path)
            if written != expected:
                raise ProtocolError("size mismatch %d != %d" % (written, expected))
            return written
        finally:
            sock.close()


class NetworkController:
    """Programmable Network Controller for Chaos Engineering & Distributed Simulation"""

    def __init__(self, socket_path=DEFAULT_SOCKET_PATH):
        self.socket_path = socket_path

    def _send_command(self, payload):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(self.socket_path)
                s.sendall(json.dumps(payload).encode('utf-8') + b"\n")
                response = s.recv(4096)
                if response:
                    return json.loads(response.decode('utf-8'))
        except Exception as e:
            return {{"error": str(e)}}
        return {{"status": "unknown"}}

    def set_latency(self, ms: int, jitter_ms: int = 0, packet_loss: float = 0.0):
        """Inject network delay in milliseconds and packet loss ratio (0.0 - 1.0)"""
        return self._send_command({{
            "action": "set_chaos",
            "latency_ms": ms,
            "jitter_ms": jitter_ms,
            "packet_loss": packet_loss
        }})

    def set_packet_loss(self, loss_rate: float):
        """Inject packet drop probability (e.g. 0.05 for 5% drop)"""
        return self.set_latency(ms=0, packet_loss=loss_rate)

    def set_partition(self, blocked: bool = True):
        """Simulate total network partition / split-brain disconnect"""
        return self._send_command({{
            "action": "set_partition",
            "blocked": blocked
        }})

    def set_bandwidth_limit(self, kbps: int):
        """Throttle network throughput (e.g. 256 for 256 Kbps)"""
        return self._send_command({{
            "action": "set_bandwidth",
            "kbps": kbps
        }})

    def reset(self):
        """Restore pristine, uninhibited network conditions"""
        return self._send_command({{"action": "reset"}})

    def get_status(self):
        """Retrieve current active chaos profile and network status"""
        return self._send_command({{"action": "get_status"}})
"#, socket = escaped_path);

        fs::write(sdk_file, content)?;
        Ok(())
    }
}
