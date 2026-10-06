"""Small explicit-cookie HTTP probe for the synthetic loopback servers."""

from __future__ import annotations

import http.client
import json
from contextlib import closing
from dataclasses import dataclass
from http.cookies import SimpleCookie
from urllib.parse import urlencode

from .server import COOKIE_NAME


@dataclass(frozen=True)
class ProbeResponse:
    status: int
    body: dict[str, object]
    set_sid: str | None
    cookie_cleared: bool
    cache_control: str | None
    set_cookie_header: str | None


class LoopbackProbe:
    def __init__(self, port: int) -> None:
        if not 1 <= port <= 65535:
            raise ValueError("invalid_loopback_port")
        self.port = port

    def request(
        self,
        method: str,
        path: str,
        *,
        sid: str | None = None,
        form: dict[str, str] | None = None,
    ) -> ProbeResponse:
        if method not in ("GET", "POST") or not path.startswith("/"):
            raise ValueError("unsupported_probe_request")
        if form is not None and (method != "POST" or path != "/login"):
            raise ValueError("form_only_for_login")
        headers = {"Connection": "close"}
        if sid is not None:
            headers["Cookie"] = f"{COOKIE_NAME}={sid}"
        payload = None
        if form is not None:
            payload = urlencode(form).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        with closing(http.client.HTTPConnection("127.0.0.1", self.port, timeout=2.0)) as connection:
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            raw = response.read(4096)
            if response.read(1):
                raise ValueError("unexpected_large_response")
            body = json.loads(raw) if raw else {}
            header = response.getheader("Set-Cookie")
            cookie = SimpleCookie()
            if header:
                cookie.load(header)
            set_sid = cookie[COOKIE_NAME].value if COOKIE_NAME in cookie else None
            return ProbeResponse(
                status=response.status,
                body=body,
                set_sid=set_sid,
                cookie_cleared=COOKIE_NAME in cookie and cookie[COOKIE_NAME].value == "" and cookie[COOKIE_NAME]["max-age"] == "0",
                cache_control=response.getheader("Cache-Control"),
                set_cookie_header=header,
            )
