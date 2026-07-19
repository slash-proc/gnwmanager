import os
import socket
from time import sleep

from gnwmanager.exceptions import DebugProbeConnectionError
from gnwmanager.ocdbackend.base import OCDBackend, TransferErrors

class GDBError(DebugProbeConnectionError):
    pass

TransferErrors.add(GDBError)

def _checksum(data: bytes) -> bytes:
    c = sum(data) % 256
    return f"{c:02x}".encode("ascii")

class GDBBackend(OCDBackend):
    def __init__(self, host: str = "localhost", port: int = 1234):
        super().__init__()
        self.version = (0, 0, 0)
        self.host = host
        self.port = port
        self._socket = None
        self._is_running = False

    def open(self) -> OCDBackend:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(5.0)
        # The GDB remote protocol here is dominated by tiny packets waiting
        # on each other's replies (a single-byte '+' ack, a short "m<addr>,4"
        # read). Without this, Nagle's algorithm on this socket combines with
        # the peer's delayed-ACK timer to add a fixed ~40ms stall to every
        # single request/response round trip -- measured directly against
        # qemu-gnw's gdbstub (a `gnwmanager --qemu info` call went from ~6.7s,
        # matching real hardware over OpenOCD, to ~39s with this unset).
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            self._socket.connect((self.host, self.port))
            self._sock_file = self._socket.makefile("rb", buffering=8192)
        except (OSError, ConnectionRefusedError) as e:
            raise DebugProbeConnectionError(f"Could not connect to QEMU GDB server at {self.host}:{self.port}. Is QEMU running with '-gdb tcp::{self.port}'?") from e
        
        # Initial handshake: Tell GDB stub what we support
        try:
            self._send_command(b"qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+")
        except GDBError:
            pass  # Some very simple stubs might not support qSupported
            
        # QEMU's GDB stub halts the VM when a client connects.
        # We explicitly resume it to match physical probe behavior.
        self.resume()
            
        return self

    def close(self):
        if self._socket:
            if hasattr(self, '_sock_file') and self._sock_file:
                self._sock_file.close()
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def _send_command(self, cmd: bytes) -> bytes:
        if not self._socket:
            raise GDBError("Socket is not open")
        
        packet = b"$" + cmd + b"#" + _checksum(cmd)
        self._socket.sendall(packet)
        
        # Wait for ack '+'
        while True:
            c = self._sock_file.read(1)
            if not c:
                raise GDBError("Connection closed by remote")
            if c == b'+':
                break
            elif c == b'-':
                self._socket.sendall(packet)
            elif c == b'$':
                # We got a packet instead of an ack. It's likely an asynchronous stop reply.
                # We need to read it, ack it, and then keep waiting for our ack or response.
                self._read_packet_data()
                
        # Wait for the actual reply packet
        while True:
            reply = self._wait_for_packet()
            # If it's a stop reply (T, S, W, X) and we didn't ask for it (cmd wasn't ? or vCont etc)
            # then it's an asynchronous notification. We should probably return it if we asked for it,
            # or ignore it if it's out of band.
            # For simplicity, if cmd is '?', we return the stop reply.
            if cmd == b'?' or not reply.startswith((b'T', b'S', b'W', b'X')):
                break
            # Otherwise we ignore the out-of-band stop reply and wait for the real reply
            
        if reply.startswith(b'E'):
            err_code = reply[1:].decode("ascii")
            raise GDBError(f"GDB error response: {err_code} for command {cmd.decode('ascii', errors='ignore')}")
            
        return reply

    def _read_packet_data(self) -> bytes:
        # Assuming '$' was just read
        reply = bytearray()
        while True:
            c = self._sock_file.read(1)
            if not c:
                raise GDBError("Connection closed by remote")
            if c == b'#':
                break
            reply.extend(c)
        # read checksum
        self._sock_file.read(2)
        # Send ack
        self._socket.sendall(b'+')
        return bytes(reply)

    def _wait_for_packet(self) -> bytes:
        while True:
            c = self._sock_file.read(1)
            if not c:
                raise GDBError("Connection closed by remote")
            if c == b'$':
                return self._read_packet_data()
            # Ignore anything else before '$'

    def read_memory(self, addr: int, size: int) -> bytes:
        if size == 0:
            return b""

        # Deliberately does NOT halt/resume around this like the other
        # accessors below: qemu-gnw's gdbstub (gdbstub/gdbstub.c, see
        # "Commit gdbstub memory-read/write non-halting fix") only gates
        # the halt-while-running check for commands other than plain 'm'/'M'
        # memory read/write -- those are serviced via cpu_memory_rw_debug(),
        # which is exactly as safe to call from a running VM as a halted
        # one. GDBBackend is QEMU-only (see cli/main.py: only ever
        # instantiated when --qemu is set; real hardware goes through
        # OCDBackend/OpenOCDBackend instead), so this is always talking to
        # that patched gdbstub. Halting/resuming around every single read
        # was previously adding two full GDB round-trips (each bounded by
        # this socket's 5s timeout, retried up to 5x by callers like
        # stm32h7b0-diag's harness.py) to every poll of a status flag --
        # confirmed root cause of multi-minute-to-hour diag-tool runs that
        # should take seconds under a heavily-loaded (near-100%-CPU) vCPU.
        CHUNK_SIZE = 4096
        result = bytearray()

        for offset in range(0, size, CHUNK_SIZE):
            chunk_size = min(CHUNK_SIZE, size - offset)
            cmd = f"m{(addr + offset):x},{chunk_size:x}".encode("ascii")
            reply = self._send_command(cmd)
            result.extend(bytes.fromhex(reply.decode("ascii")))

        return bytes(result)

    def write_memory(self, addr: int, data: bytes):
        if not data:
            return

        # See read_memory()'s comment: 'M' is exempted from the halt gate
        # by the same qemu-gnw gdbstub patch, so no halt/resume needed here
        # either.
        CHUNK_SIZE = 4096
        for offset in range(0, len(data), CHUNK_SIZE):
            chunk = data[offset:offset+CHUNK_SIZE]
            hex_data = chunk.hex()
            cmd = f"M{(addr + offset):x},{len(chunk):x}:{hex_data}".encode("ascii")
            reply = self._send_command(cmd)

            if reply != b"OK":
                raise GDBError(f"Failed to write memory, expected OK got {reply}")

    def _get_reg_idx(self, name: str) -> int:
        name = name.lower()
        mapping = {
            "sp": 13,
            "msp": 13,
            "lr": 14,
            "pc": 15,
            "xpsr": 16,
        }
        if name in mapping:
            return mapping[name]
        if name.startswith("r"):
            try:
                return int(name[1:])
            except ValueError:
                pass
        raise ValueError(f"Unknown register {name}")

    def read_register(self, name: str) -> int:
        was_running = self._is_running
        if was_running:
            self.halt()
            
        idx = self._get_reg_idx(name)
        cmd = f"p{idx:x}".encode("ascii")
        reply = self._send_command(cmd)
        
        if was_running:
            self.resume()
            
        # GDB returns little-endian hex string for registers usually
        data = bytes.fromhex(reply.decode("ascii"))
        return int.from_bytes(data, byteorder="little")

    def write_register(self, name: str, val: int):
        was_running = self._is_running
        if was_running:
            self.halt()
            
        idx = self._get_reg_idx(name)
        # 32-bit registers, little-endian hex string
        hex_val = val.to_bytes(4, byteorder="little").hex()
        cmd = f"P{idx:x}={hex_val}".encode("ascii")
        reply = self._send_command(cmd)
        
        if was_running:
            self.resume()
            
        if reply != b"OK":
            raise GDBError(f"Failed to write register, expected OK got {reply}")

    def set_frequency(self, freq: int):
        # Ignored for emulated environment
        pass

    def reset(self):
        was_running = self._is_running
        if was_running:
            self.halt()
            
        # QEMU reset might be 'R00' or 'monitor system_reset'
        cmd = b"qRcmd," + b"system_reset".hex().encode("ascii")
        try:
            self._send_command(cmd)
        except GDBError:
            pass
            
        if was_running:
            self.resume()
        else:
            self._is_running = False

    def halt(self):
        # Send Ctrl-C to interrupt
        if not self._socket:
            raise GDBError("Socket is not open")
        self._socket.sendall(b"\x03")
        # Try to query the current state instead of waiting blindly for an out-of-band stop reply
        try:
            self._send_command(b"?")
        except socket.timeout:
            raise GDBError("Timeout waiting for target to halt")
        self._is_running = False

    def reset_and_halt(self):
        self.reset()
        self.halt()

    # Override resume specifically for the blocking nature
    def resume(self):
        if not self._socket:
            raise GDBError("Socket is not open")
        cmd = b"c"
        packet = b"$" + cmd + b"#" + _checksum(cmd)
        self._socket.sendall(packet)
        # Wait for ack
        while True:
            ack = self._sock_file.read(1)
            if ack == b'+':
                break
            elif ack == b'-':
                self._socket.sendall(packet)
            elif not ack:
                raise GDBError("Connection closed by remote")
        # Do NOT wait for '$' here because 'c' replies only when target stops.
        self._is_running = True

    def start_gdbserver(self, port, logging=True, blocking=True):
        pass # QEMU is already the GDB server

    @property
    def probe_name(self) -> str:
        return "QEMU Emulator"
