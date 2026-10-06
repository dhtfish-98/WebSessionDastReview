"""Two loopback-only HTTP variants for session lifecycle and ownership tests."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


USERS = {"alice": "alice-lab-secret", "bob": "bob-lab-secret"}
RECORDS = {
    "alice-note": {"owner": "alice", "value": "ALICE_PRIVATE_FIXTURE"},
    "bob-note": {"owner": "bob", "value": "BOB_PRIVATE_FIXTURE"},
}
COOKIE_NAME = "lab_sid"


def fingerprint(sid: str | None) -> str | None:
    """Receipt-safe comparison label; the full bearer value is never logged."""
    return hashlib.sha256(sid.encode("ascii")).hexdigest()[:16] if sid else None


@dataclass(frozen=True)
class Session:
    account: str | None


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()

    def issue(self, account: str | None = None) -> str:
        with self._lock:
            while True:
                sid = secrets.token_urlsafe(32)
                if sid not in self._sessions:
                    self._sessions[sid] = Session(account)
                    return sid

    def lookup(self, sid: str | None) -> Session | None:
        with self._lock:
            return self._sessions.get(sid) if sid else None

    def weak_bind(self, sid: str, account: str) -> None:
        with self._lock:
            if sid not in self._sessions:
                raise ValueError("unknown_session")
            self._sessions[sid] = Session(account)

    def rotate_after_login(self, sid: str, account: str) -> str:
        with self._lock:
            if sid not in self._sessions:
                raise ValueError("unknown_session")
            del self._sessions[sid]
            return self.issue(account)

    def invalidate(self, sid: str) -> None:
        with self._lock:
            self._sessions.pop(sid, None)


class _LoopbackServer(ThreadingHTTPServer):
    daemon_threads = True


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(2.0)

    @property
    def lab(self) -> SessionLab:
        return self.server.lab  # type: ignore[attr-defined]

    def _sid(self) -> str | None:
        raw = self.headers.get("Cookie", "")
        if raw.count(f"{COOKIE_NAME}=") != 1:
            return None
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return None
        return jar[COOKIE_NAME].value if COOKIE_NAME in jar else None

    def _reply(
        self, status: HTTPStatus,
        data: dict[str, object] | None = None,
        *,
        set_sid: str | None = None,
        clear_sid: bool = False,
    ) -> None:
        body = json.dumps(data or {}, sort_keys=True, separators=(",", ":")).encode("utf-8") if status != HTTPStatus.NO_CONTENT else b""
        with self.lab.lock:
            self.lab.requests.append({"method": self.command, "path": self.path, "status": int(status), "sid_fingerprint": fingerprint(self._sid())})
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        if set_sid is not None:
            self.send_header("Set-Cookie", f"{COOKIE_NAME}={set_sid}; Path=/; HttpOnly; SameSite=Lax")
        elif clear_sid:
            self.send_header("Set-Cookie", f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True

    def _route(self) -> str:
        parsed = urlsplit(self.path)
        return parsed.path if not parsed.query and not parsed.fragment else ""

    def do_GET(self) -> None:
        route = self._route()
        sid = self._sid()
        session = self.lab.sessions.lookup(sid)
        if route == "/start":
            if session is None:
                sid = self.lab.sessions.issue()
            self._reply(HTTPStatus.OK, {"stage": "anonymous" if session is None else "existing"}, set_sid=sid)
            return
        if route == "/me":
            if session is None or session.account is None:
                self._reply(HTTPStatus.UNAUTHORIZED, {"error": "authentication_required"})
            else:
                self._reply(HTTPStatus.OK, {"account": session.account})
            return
        if route.startswith("/records/") and route.count("/") == 2:
            record_id = route.rsplit("/", 1)[1]
            record = RECORDS.get(record_id)
            if session is None or session.account is None:
                self._reply(HTTPStatus.UNAUTHORIZED, {"error": "authentication_required"})
            elif record is None:
                self._reply(HTTPStatus.NOT_FOUND, {"error": "missing_record"})
            elif self.lab.variant == "fixed" and record["owner"] != session.account:
                self._reply(HTTPStatus.FORBIDDEN, {"error": "not_owner"})
            else:
                self._reply(HTTPStatus.OK, {"record_id": record_id, **record})
            return
        self._reply(HTTPStatus.NOT_FOUND, {"error": "unknown_route"})

    def do_POST(self) -> None:
        route = self._route()
        sid = self._sid()
        session = self.lab.sessions.lookup(sid)
        if route == "/logout":
            if session is None or session.account is None:
                self._reply(HTTPStatus.UNAUTHORIZED, {"error": "authentication_required"})
                return
            if self.lab.variant == "fixed":
                self.lab.sessions.invalidate(sid)
            self._reply(HTTPStatus.NO_CONTENT, clear_sid=True)
            return
        if route != "/login":
            self._reply(HTTPStatus.NOT_FOUND, {"error": "unknown_route"})
            return
        if session is None:
            self._reply(HTTPStatus.BAD_REQUEST, {"error": "start_session_first"})
            return
        if self.headers.get("Content-Type") != "application/x-www-form-urlencoded":
            self._reply(HTTPStatus.BAD_REQUEST, {"error": "invalid_form"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
            if not 1 <= length <= 512:
                raise ValueError("form_size")
            form = parse_qs(self.rfile.read(length).decode("ascii"), strict_parsing=True)
            if set(form) != {"username", "password"} or any(len(v) != 1 for v in form.values()):
                raise ValueError("form_fields")
            account = form["username"][0]
            password = form["password"][0]
        except (ValueError, UnicodeDecodeError):
            self._reply(HTTPStatus.BAD_REQUEST, {"error": "invalid_form"})
            return
        expected = USERS.get(account)
        if expected is None or not hmac.compare_digest(password, expected):
            self._reply(HTTPStatus.UNAUTHORIZED, {"error": "invalid_credentials"})
            return
        if self.lab.variant == "fixed":
            new_sid = self.lab.sessions.rotate_after_login(sid, account)
        else:
            self.lab.sessions.weak_bind(sid, account)
            new_sid = sid
        self._reply(HTTPStatus.OK, {"account": account}, set_sid=new_sid)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class SessionLab:
    """An intentionally limited fixture, never a public web service."""

    def __init__(self, variant: str) -> None:
        if variant not in ("weak_baseline", "fixed"):
            raise ValueError("unknown_variant")
        self.variant = variant
        self.sessions = SessionStore()
        self.lock = threading.Lock()
        self.requests: list[dict[str, object]] = []
        self._server: _LoopbackServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("lab_not_started")
        return self._server.server_address[1]

    def __enter__(self) -> SessionLab:
        server = _LoopbackServer(("127.0.0.1", 0), _Handler)
        server.lab = self  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=1)
