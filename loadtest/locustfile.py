"""High-performance RADIUS load test using raw UDP sockets.

Replaces pyrad with pre-built packet templates and minimal per-request
overhead (one os.urandom + one MD5 + raw sendto/recvfrom).
"""

from gevent import monkey
monkey.patch_all()

import hashlib
import os
import random
import socket
import struct
import time

from locust import User, constant_pacing, tag, task

RADIUS_HOSTS = os.environ.get("RADIUS_HOSTS", os.environ.get("RADIUS_HOST", "freeradius")).split(",")
RADIUS_SECRET = os.environ.get("RADIUS_SECRET", "testing123").encode()

# RADIUS codes
ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ACCOUNTING_REQUEST = 4
ACCOUNTING_RESPONSE = 5

# Resolve all hosts once at import time
_RESOLVED_HOSTS = None


def _resolve_hosts():
    global _RESOLVED_HOSTS
    if _RESOLVED_HOSTS is None:
        _RESOLVED_HOSTS = [socket.gethostbyname(h.strip()) for h in RADIUS_HOSTS]
    return _RESOLVED_HOSTS


def _encode_attr(attr_type: int, value: bytes) -> bytes:
    return struct.pack("!BB", attr_type, len(value) + 2) + value


def _pap_encrypt(password: str, secret: bytes, authenticator: bytes) -> bytes:
    """Encrypt password per RFC 2865 section 5.2."""
    padded = password.encode().ljust(16, b"\x00")[:128]
    result = b""
    last = authenticator
    for i in range(0, len(padded), 16):
        h = hashlib.md5(secret + last).digest()
        block = bytes(padded[i + j] ^ h[j] for j in range(16))
        result += block
        last = block
    return result


def _build_auth_packet(username: str, password: str, nas_port: int,
                       identifier: int, authenticator: bytes) -> bytes:
    """Build a complete Access-Request packet."""
    attrs = b""
    attrs += _encode_attr(1, username.encode())  # User-Name
    attrs += _encode_attr(2, _pap_encrypt(password, RADIUS_SECRET, authenticator))  # User-Password
    attrs += _encode_attr(4, socket.inet_aton("127.0.0.1"))  # NAS-IP-Address
    attrs += _encode_attr(5, struct.pack("!I", nas_port))  # NAS-Port

    length = 20 + len(attrs)
    header = struct.pack("!BBH", ACCESS_REQUEST, identifier, length) + authenticator
    return header + attrs


def _build_acct_packet(username: str, status_type: int, session_id: str,
                       identifier: int, session_time: int = 0,
                       input_octets: int = 0, output_octets: int = 0) -> bytes:
    """Build a complete Accounting-Request packet with computed authenticator."""
    attrs = b""
    attrs += _encode_attr(1, username.encode())  # User-Name
    attrs += _encode_attr(40, struct.pack("!I", status_type))  # Acct-Status-Type
    attrs += _encode_attr(44, session_id.encode())  # Acct-Session-Id
    attrs += _encode_attr(4, socket.inet_aton("127.0.0.1"))  # NAS-IP-Address
    attrs += _encode_attr(5, struct.pack("!I", 0))  # NAS-Port
    attrs += _encode_attr(8, socket.inet_aton("10.0.0.2"))  # Framed-IP-Address

    if session_time:
        attrs += _encode_attr(46, struct.pack("!I", session_time))
    if input_octets:
        attrs += _encode_attr(42, struct.pack("!I", input_octets))
    if output_octets:
        attrs += _encode_attr(43, struct.pack("!I", output_octets))

    length = 20 + len(attrs)
    # Accounting authenticator = MD5(Code+ID+Length+16 zero bytes+Attrs+Secret)
    zero_auth = b"\x00" * 16
    header = struct.pack("!BBH", ACCOUNTING_REQUEST, identifier, length)
    authenticator = hashlib.md5(header + zero_auth + attrs + RADIUS_SECRET).digest()
    return header + authenticator + attrs


def _session_id() -> str:
    return "%016x" % random.getrandbits(64)


class RadiusUser(User):
    wait_time = constant_pacing(0)

    def on_start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(1)
        host = random.choice(_resolve_hosts())
        self._addr = (host, 1812)
        self._acct_addr = (host, 1813)
        self._id = 0

    def on_stop(self):
        self._sock.close()

    def _next_id(self) -> int:
        self._id = (self._id + 1) % 256
        return self._id

    def _send_auth(self, username: str, password: str, name: str):
        identifier = self._next_id()
        authenticator = os.urandom(16)
        pkt = _build_auth_packet(username, password, 0, identifier, authenticator)

        start = time.perf_counter()
        try:
            self._sock.sendto(pkt, self._addr)
            data = self._sock.recv(4096)
            elapsed_ms = (time.perf_counter() - start) * 1000

            code = data[0]
            if code == ACCESS_ACCEPT:
                result = "Access-Accept"
            elif code == ACCESS_REJECT:
                result = "Access-Reject"
            else:
                result = f"code={code}"

            self.environment.events.request.fire(
                request_type="RADIUS",
                name=name,
                response_time=elapsed_ms,
                response_length=len(data),
                exception=None,
                context={"result": result},
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self.environment.events.request.fire(
                request_type="RADIUS",
                name=name,
                response_time=elapsed_ms,
                response_length=0,
                exception=e,
            )

    def _send_acct(self, status_type: int, name: str, **kwargs):
        identifier = self._next_id()
        pkt = _build_acct_packet("subscriber1", status_type, _session_id(),
                                 identifier, **kwargs)

        start = time.perf_counter()
        try:
            self._sock.sendto(pkt, self._acct_addr)
            data = self._sock.recv(4096)
            elapsed_ms = (time.perf_counter() - start) * 1000

            self.environment.events.request.fire(
                request_type="RADIUS",
                name=name,
                response_time=elapsed_ms,
                response_length=len(data),
                exception=None,
                context={"result": "Accounting-Response"},
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self.environment.events.request.fire(
                request_type="RADIUS",
                name=name,
                response_time=elapsed_ms,
                response_length=0,
                exception=e,
            )

    @tag("auth")
    @task(10)
    def auth_valid(self):
        self._send_auth("subscriber1", "secret123", "Access-Request (valid)")

    @tag("auth")
    @task(3)
    def auth_bad_password(self):
        self._send_auth("subscriber1", "wrongpass", "Access-Request (bad pass)")

    @tag("auth")
    @task(1)
    def auth_unknown_user(self):
        self._send_auth("nonexistent", "whatever", "Access-Request (unknown user)")

    @tag("acct")
    @task(3)
    def acct_start(self):
        self._send_acct(1, "Accounting-Request (Start)")

    @tag("acct")
    @task(2)
    def acct_interim(self):
        self._send_acct(3, "Accounting-Request (Interim)",
                        session_time=300, input_octets=1048576, output_octets=5242880)

    @tag("acct")
    @task(1)
    def acct_stop(self):
        self._send_acct(2, "Accounting-Request (Stop)",
                        session_time=3600, input_octets=104857600, output_octets=524288000)
