import contextlib
import socket

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
        # qemu-gnw's gdbstub (a `gnwmanager --backend gdb info` call went from ~6.7s,
        # matching real hardware over OpenOCD, to ~39s with this unset).
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            self._socket.connect((self.host, self.port))
            self._sock_file = self._socket.makefile("rb", buffering=8192)
        except (OSError, ConnectionRefusedError) as e:
            raise DebugProbeConnectionError(
                f"Could not connect to QEMU GDB server at {self.host}:{self.port}. "
                f"Is QEMU running with '-gdb tcp::{self.port}'?"
            ) from e

        # Initial handshake: Tell GDB stub what we support
        # Some very simple stubs might not support qSupported
        with contextlib.suppress(GDBError):
            self._send_command(b"qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn+")

        # QEMU's GDB stub halts the VM when a client connects.
        # We explicitly resume it to match physical probe behavior.
        self.resume()

        return self

    def close(self):
        if self._socket:
            if hasattr(self, "_sock_file") and self._sock_file:
                self._sock_file.close()
            with contextlib.suppress(OSError):
                self._socket.close()
            self._socket = None
        self._is_running = False

    def _read(self, n: int) -> bytes:
        """Read exactly ``n`` bytes, translating socket failures into GDBError.

        The socket carries a 5s timeout (see open()); without this translation a
        raw socket.timeout would escape past TransferErrors' retry machinery and
        main.py's DebugProbeConnectionError handling.
        """
        try:
            data = self._sock_file.read(n)
        except socket.timeout as e:
            raise GDBError(f"Timed out waiting for {n} byte(s) from the GDB stub") from e
        except OSError as e:
            raise GDBError(f"Socket error while reading from the GDB stub: {e}") from e
        if not data:
            raise GDBError("Connection closed by remote")
        return data

    def _write(self, data: bytes):
        """Send all of ``data``, translating socket failures into GDBError."""
        if not self._socket:
            raise GDBError("Socket is not open")
        try:
            self._socket.sendall(data)
        except socket.timeout as e:
            raise GDBError("Timed out sending to the GDB stub") from e
        except OSError as e:
            raise GDBError(f"Socket error while writing to the GDB stub: {e}") from e

    def _send_command(self, cmd: bytes) -> bytes:
        if not self._socket:
            raise GDBError("Socket is not open")

        packet = b"$" + cmd + b"#" + _checksum(cmd)
        self._write(packet)

        # Wait for ack '+'
        while True:
            c = self._read(1)
            if c == b"+":
                break
            elif c == b"-":
                self._write(packet)
            elif c == b"$":
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
            if cmd == b"?" or not reply.startswith((b"T", b"S", b"W", b"X")):
                break
            # Otherwise we ignore the out-of-band stop reply and wait for the real reply

        if reply.startswith(b"E"):
            err_code = reply[1:].decode("ascii")
            raise GDBError(f"GDB error response: {err_code} for command {cmd.decode('ascii', errors='ignore')}")

        return reply

    def _read_packet_data(self) -> bytes:
        # Assuming '$' was just read
        reply = bytearray()
        while True:
            c = self._read(1)
            if c == b"#":
                break
            if c == b"*":
                # Run-length encoding: the previous byte repeats an additional
                # (count_char - 29) times. QEMU's gdbstub does not currently
                # emit this on replies (gdb_put_packet_binary() copies the
                # payload verbatim; its RLE handling is receive-side only), but
                # the remote protocol permits any stub to, so decode it.
                if not reply:
                    raise GDBError("Malformed packet: RLE marker with no preceding byte")
                repeat = self._read(1)[0] - 29
                if repeat < 0:
                    raise GDBError("Malformed packet: invalid RLE repeat count")
                reply.extend(reply[-1:] * repeat)
                continue
            reply.extend(c)
        # read checksum
        self._read(2)
        # Send ack
        self._write(b"+")
        return bytes(reply)

    def _wait_for_packet(self) -> bytes:
        while True:
            c = self._read(1)
            if c == b"$":
                return self._read_packet_data()
            # Ignore anything else before '$'

    def read_memory(self, addr: int, size: int) -> bytes:
        if size == 0:
            return b""

        # Deliberately does NOT halt/resume around this like the other accessors
        # below. Plain 'm'/'M' memory access is serviced by QEMU's gdbstub via
        # cpu_memory_rw_debug(), which is exactly as safe to call against a
        # running VM as a halted one. Halting/resuming around every single read
        # added two full GDB round-trips (each bounded by this socket's 5s
        # timeout) to every poll of a status flag, which under a heavily-loaded
        # vCPU turned runs that should take seconds into minutes.
        chunk_size_max = 4096
        result = bytearray()

        for offset in range(0, size, chunk_size_max):
            chunk_size = min(chunk_size_max, size - offset)
            cmd = f"m{(addr + offset):x},{chunk_size:x}".encode("ascii")
            reply = self._send_command(cmd)
            chunk = self._decode_hex(reply, cmd)
            # A stub is permitted to return fewer bytes than requested; without
            # this check that would silently yield truncated data to callers.
            if len(chunk) != chunk_size:
                raise GDBError(f"Short read at 0x{addr + offset:08x}: requested {chunk_size} bytes, got {len(chunk)}")
            result.extend(chunk)

        return bytes(result)

    @staticmethod
    def _decode_hex(reply: bytes, cmd: bytes) -> bytes:
        """Decode a hex-string reply, raising GDBError rather than ValueError."""
        try:
            return bytes.fromhex(reply.decode("ascii"))
        except (ValueError, UnicodeDecodeError) as e:
            raise GDBError(f"Malformed hex reply {reply!r} for command {cmd.decode('ascii', errors='ignore')}") from e

    def write_memory(self, addr: int, data: bytes):
        if not data:
            return

        # See read_memory()'s comment: 'M' goes through the same
        # cpu_memory_rw_debug() path, so no halt/resume is needed here either.
        chunk_size_max = 4096
        for offset in range(0, len(data), chunk_size_max):
            chunk = data[offset : offset + chunk_size_max]
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
        data = self._decode_hex(reply, cmd)
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
        if self._is_running:
            self.halt()

        # 'monitor system_reset'. Failures propagate: silently suppressing them
        # would report a successful reset having reset nothing.
        cmd = b"qRcmd," + b"system_reset".hex().encode("ascii")
        self._send_command(cmd)

        # Matches OpenOCDBackend/PyOCDBackend, whose reset() unconditionally
        # leaves the target running regardless of its prior state.
        self.resume()

    def halt(self):
        # Send Ctrl-C to interrupt
        self._write(b"\x03")
        # Try to query the current state instead of waiting blindly for an out-of-band stop reply
        self._send_command(b"?")
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
        self._write(packet)
        # Wait for ack
        while True:
            ack = self._read(1)
            if ack == b"+":
                break
            elif ack == b"-":
                self._write(packet)
        # Do NOT wait for '$' here because 'c' replies only when target stops.
        self._is_running = True

    def start_gdbserver(self, port, logging=True, blocking=True):
        # QEMU is itself the GDB server, and its stub accepts only a single
        # client -- which this backend is already occupying. Returning silently
        # would leave `gnwmanager gdbserver` exiting instantly and `gnwmanager
        # gdb` launching gdb against a port nothing is listening on.
        raise NotImplementedError(
            f"QEMU is already the GDB server on port {self.port}. Connect gdb to it directly with "
            f"'target extended-remote {self.host}:{self.port}' (without a concurrent gnwmanager session, "
            f"since QEMU's gdbstub accepts only one client)."
        )

    @property
    def probe_name(self) -> str:
        return "QEMU Emulator"
