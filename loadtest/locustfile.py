"""Load tests that send real RADIUS packets to FreeRADIUS via pyrad.

Each Locust user opens its own UDP socket and sends Access-Request or
Accounting-Request packets, measuring the full round-trip through
FreeRADIUS -> auth-svc/acct-svc and back.
"""

import os
import random
import string
import time

import pyrad.packet
from locust import User, between, tag, task
from pyrad.client import Client
from pyrad.dictionary import Dictionary

RADIUS_HOST = os.environ.get("RADIUS_HOST", "freeradius")
RADIUS_SECRET = os.environ.get("RADIUS_SECRET", "testing123").encode()
DICT_PATH = os.environ.get("RADIUS_DICT", "/app/dictionary")


def _session_id() -> str:
    return "".join(random.choices(string.hexdigits[:16], k=16))


def _make_client() -> Client:
    client = Client(
        server=RADIUS_HOST,
        secret=RADIUS_SECRET,
        dict=Dictionary(DICT_PATH),
    )
    client.timeout = 10
    client.retries = 1
    return client


class RadiusUser(User):
    wait_time = between(0.01, 0.05)

    def on_start(self):
        self.rad = _make_client()

    def _send(self, packet, request_type: str, name: str):
        start = time.perf_counter()
        exc = None
        try:
            reply = self.rad.SendPacket(packet)
            elapsed_ms = (time.perf_counter() - start) * 1000

            if reply.code == pyrad.packet.AccessAccept:
                result = "Access-Accept"
            elif reply.code == pyrad.packet.AccessReject:
                result = "Access-Reject"
            elif reply.code == pyrad.packet.AccountingResponse:
                result = "Accounting-Response"
            else:
                result = f"code={reply.code}"

            self.environment.events.request.fire(
                request_type=request_type,
                name=name,
                response_time=elapsed_ms,
                response_length=0,
                exception=None,
                context={"result": result},
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            exc = e
            self.environment.events.request.fire(
                request_type=request_type,
                name=name,
                response_time=elapsed_ms,
                response_length=0,
                exception=exc,
            )

    @tag("auth")
    @task(10)
    def auth_valid(self):
        req = self.rad.CreateAuthPacket(
            code=pyrad.packet.AccessRequest,
            User_Name="subscriber1",
            NAS_IP_Address="127.0.0.1",
            NAS_Port=0,
        )
        req["User-Password"] = req.PwCrypt("secret123")
        self._send(req, "RADIUS", "Access-Request (valid)")

    @tag("auth")
    @task(3)
    def auth_bad_password(self):
        req = self.rad.CreateAuthPacket(
            code=pyrad.packet.AccessRequest,
            User_Name="subscriber1",
            NAS_IP_Address="127.0.0.1",
            NAS_Port=0,
        )
        req["User-Password"] = req.PwCrypt("wrongpass")
        self._send(req, "RADIUS", "Access-Request (bad pass)")

    @tag("auth")
    @task(1)
    def auth_unknown_user(self):
        req = self.rad.CreateAuthPacket(
            code=pyrad.packet.AccessRequest,
            User_Name="nonexistent",
            NAS_IP_Address="127.0.0.1",
            NAS_Port=0,
        )
        req["User-Password"] = req.PwCrypt("whatever")
        self._send(req, "RADIUS", "Access-Request (unknown user)")

    @tag("acct")
    @task(3)
    def acct_start(self):
        req = self.rad.CreateAcctPacket(
            code=pyrad.packet.AccountingRequest,
            User_Name="subscriber1",
            NAS_IP_Address="127.0.0.1",
            NAS_Port=0,
        )
        req["Acct-Status-Type"] = "Start"
        req["Acct-Session-Id"] = _session_id()
        req["Framed-IP-Address"] = "10.0.0.2"
        self._send(req, "RADIUS", "Accounting-Request (Start)")

    @tag("acct")
    @task(2)
    def acct_interim(self):
        req = self.rad.CreateAcctPacket(
            code=pyrad.packet.AccountingRequest,
            User_Name="subscriber1",
            NAS_IP_Address="127.0.0.1",
            NAS_Port=0,
        )
        req["Acct-Status-Type"] = "Interim-Update"
        req["Acct-Session-Id"] = _session_id()
        req["Acct-Session-Time"] = 300
        req["Acct-Input-Octets"] = 1048576
        req["Acct-Output-Octets"] = 5242880
        req["Framed-IP-Address"] = "10.0.0.2"
        self._send(req, "RADIUS", "Accounting-Request (Interim)")

    @tag("acct")
    @task(1)
    def acct_stop(self):
        req = self.rad.CreateAcctPacket(
            code=pyrad.packet.AccountingRequest,
            User_Name="subscriber1",
            NAS_IP_Address="127.0.0.1",
            NAS_Port=0,
        )
        req["Acct-Status-Type"] = "Stop"
        req["Acct-Session-Id"] = _session_id()
        req["Acct-Session-Time"] = 3600
        req["Acct-Input-Octets"] = 104857600
        req["Acct-Output-Octets"] = 524288000
        req["Framed-IP-Address"] = "10.0.0.2"
        self._send(req, "RADIUS", "Accounting-Request (Stop)")
