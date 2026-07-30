import socket

import pytest

from gnwmanager.ocdbackend.gdb_backend import GDBBackend, GDBError, _checksum


class FakeSockFile:
    """Stands in for the socket's buffered file object."""

    def __init__(self, data: bytes, raise_timeout: bool = False):
        self.data = data
        self.pos = 0
        self.raise_timeout = raise_timeout

    def read(self, n: int) -> bytes:
        if self.raise_timeout:
            raise socket.timeout
        chunk = self.data[self.pos : self.pos + n]
        self.pos += len(chunk)
        return chunk

    def close(self):
        pass


class FakeSocket:
    def __init__(self):
        self.sent = bytearray()

    def sendall(self, data: bytes):
        self.sent.extend(data)

    def close(self):
        pass


def make_backend(reply_stream: bytes, raise_timeout: bool = False) -> GDBBackend:
    backend = GDBBackend()
    backend._socket = FakeSocket()
    backend._sock_file = FakeSockFile(reply_stream, raise_timeout=raise_timeout)
    return backend


def packet(payload: bytes) -> bytes:
    """Wrap a raw (already-encoded) payload as an acked reply packet."""
    return b"+$" + payload + b"#" + _checksum(payload)


def test_rle_is_expanded():
    # RLE repeats the preceding *character* of the packet stream, i.e. a hex
    # nibble. "ff*!" -> 'f' plus 4 more (ord('!') - 29) -> "ffffff" -> 3 bytes.
    backend = make_backend(packet(b"ff*!"))
    assert backend.read_memory(0x2000_0000, 3) == b"\xff\xff\xff"


def test_rle_without_preceding_byte_is_an_error():
    backend = make_backend(packet(b"* "))
    with pytest.raises(GDBError, match="RLE marker with no preceding byte"):
        backend.read_memory(0x2000_0000, 1)


def test_rle_invalid_repeat_count_is_an_error():
    backend = make_backend(packet(b"ff*\x01"))
    with pytest.raises(GDBError, match="invalid RLE repeat count"):
        backend.read_memory(0x2000_0000, 1)


def test_short_read_is_detected():
    # Asked for 4 bytes, stub returns 2.
    backend = make_backend(packet(b"deadbeef"[:4]))
    with pytest.raises(GDBError, match="Short read"):
        backend.read_memory(0x2000_0000, 4)


def test_read_memory_happy_path():
    backend = make_backend(packet(b"deadbeef"))
    assert backend.read_memory(0x2000_0000, 4) == b"\xde\xad\xbe\xef"


def test_malformed_hex_raises_gdb_error_not_value_error():
    backend = make_backend(packet(b"zzzz"))
    with pytest.raises(GDBError, match="Malformed hex reply"):
        backend.read_memory(0x2000_0000, 2)


def test_timeout_is_translated_to_gdb_error():
    backend = make_backend(b"", raise_timeout=True)
    with pytest.raises(GDBError, match="Timed out"):
        backend.read_memory(0x2000_0000, 4)


def test_closed_connection_is_translated_to_gdb_error():
    backend = make_backend(b"")
    with pytest.raises(GDBError, match="Connection closed by remote"):
        backend.read_memory(0x2000_0000, 4)


def test_error_reply_raises_gdb_error():
    backend = make_backend(packet(b"E01"))
    with pytest.raises(GDBError, match="GDB error response"):
        backend.read_memory(0x2000_0000, 4)


def test_reset_leaves_target_running():
    # Reply to the halt '?' query, then to qRcmd. resume() only needs an ack.
    backend = make_backend(packet(b"T05") + packet(b"OK") + b"+")
    backend._is_running = True
    backend.reset()
    assert backend._is_running is True


def test_reset_propagates_failure():
    backend = make_backend(packet(b"E01"))
    with pytest.raises(GDBError):
        backend.reset()


def test_start_gdbserver_raises_with_actionable_message():
    backend = GDBBackend(port=1234)
    with pytest.raises(NotImplementedError, match="already the GDB server on port 1234"):
        backend.start_gdbserver(3333)


def test_close_resets_running_state():
    backend = make_backend(b"")
    backend._is_running = True
    backend.close()
    assert backend._is_running is False
