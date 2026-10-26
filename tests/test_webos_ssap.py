# SPDX-License-Identifier: AGPL-3.0-or-later
"""Transport edge cases with in-memory sockets, never a TV connection."""
import base64
import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'tools'))
from webos_ssap import SSAPError, WebSocket, WS_GUID


class SocketFixture:
    def __init__(self, received):
        self.received = received
        self.sent = b''
        self.closed = False

    def sendall(self, data):
        self.sent += data

    def recv(self, count):
        data, self.received = self.received[:count], self.received[count:]
        return data

    def settimeout(self, _timeout):
        pass

    def close(self):
        self.closed = True


class WebSocketTests(unittest.TestCase):
    def test_handshake_validates_accept_and_preserves_a_coalesced_first_frame(self):
        nonce = bytes(16)
        key = base64.b64encode(nonce).decode()
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest())
        response = b'HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n'
        sock = SocketFixture(response + b'\x81\x02{}')
        with (patch('webos_ssap.socket.create_connection', return_value=sock),
              patch('webos_ssap.os.urandom', return_value=nonce)):
            ws = WebSocket.connect('192.0.2.10', secure=False)
        self.assertEqual(ws.recv_text(), '{}')

    def test_mismatched_handshake_accept_is_rejected(self):
        sock = SocketFixture(b'HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: wrong\r\n\r\n')
        with patch('webos_ssap.socket.create_connection', return_value=sock):
            with self.assertRaisesRegex(SSAPError, 'accept'):
                WebSocket.connect('192.0.2.10', secure=False)
        self.assertTrue(sock.closed)

    def test_oversized_frames_fail_before_receiving_the_body(self):
        sock = SocketFixture(b'\x81\x7f' + struct.pack('!Q', 1024 * 1024 + 1))
        with self.assertRaisesRegex(SSAPError, '1 MiB'):
            WebSocket(sock).recv_text()


if __name__ == '__main__':
    unittest.main()
