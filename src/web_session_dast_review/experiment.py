"""Exercise both self-owned session variants through real loopback HTTP."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
from pathlib import Path

from .http_probe import LoopbackProbe, ProbeResponse
from .server import SessionLab, fingerprint


def _expect(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(label)


def _run_variant(variant: str) -> dict[str, object]:
    matrix: list[dict[str, object]] = []
    expected_weak = variant == "weak_baseline"

    with SessionLab(variant) as lab:
        probe = LoopbackProbe(lab.port)

        def capture(label: str, method: str, path: str, response: ProbeResponse, expected_status: int, sid: str | None = None) -> None:
            _expect(response.status == expected_status, f"{variant}:{label}:{response.status}")
            _expect(response.cache_control == "no-store", f"{variant}:{label}:cache")
            matrix.append({
                "step": label,
                "method": method,
                "path": path,
                "sent_sid_fingerprint": fingerprint(sid),
                "status": response.status,
                "expected_status": expected_status,
                "body": response.body,
                "set_sid_fingerprint": fingerprint(response.set_sid),
                "cookie_cleared": response.cookie_cleared,
                "check": "PASS",
            })

        first = probe.request("GET", "/start")
        capture("alice_anonymous_start", "GET", "/start", first, 200)
        alice_pre = first.set_sid
        _expect(bool(alice_pre), f"{variant}:missing_pre_login_id")

        response = probe.request("GET", "/me", sid=alice_pre)
        capture("anonymous_identity_denied", "GET", "/me", response, 401, alice_pre)
        response = probe.request("GET", "/me", sid="chosen-but-never-issued")
        capture("arbitrary_id_not_accepted", "GET", "/me", response, 401, "chosen-but-never-issued")
        response = probe.request("POST", "/login", sid=alice_pre, form={"username": "alice", "password": "wrong-lab-secret"})
        capture("bad_password_denied", "POST", "/login", response, 401, alice_pre)
        response = probe.request("GET", "/me", sid=alice_pre)
        capture("bad_password_did_not_bind", "GET", "/me", response, 401, alice_pre)

        login = probe.request("POST", "/login", sid=alice_pre, form={"username": "alice", "password": "alice-lab-secret"})
        capture("alice_login", "POST", "/login", login, 200, alice_pre)
        alice_auth = login.set_sid
        _expect(bool(alice_auth), f"{variant}:missing_auth_id")
        _expect((alice_auth == alice_pre) == expected_weak, f"{variant}:rotation_invariant")
        _expect(login.set_cookie_header is not None and "HttpOnly" in login.set_cookie_header and "SameSite=Lax" in login.set_cookie_header, f"{variant}:cookie_attrs")

        old = probe.request("GET", "/me", sid=alice_pre)
        capture("pre_login_id_after_login", "GET", "/me", old, 200 if expected_weak else 401, alice_pre)
        _expect((old.body.get("account") == "alice") == expected_weak, f"{variant}:old_id_auth_body")
        response = probe.request("GET", "/me", sid=alice_auth)
        capture("alice_authenticated_identity", "GET", "/me", response, 200, alice_auth)
        _expect(response.body.get("account") == "alice", f"{variant}:alice_identity")
        response = probe.request("GET", "/records/alice-note", sid=alice_auth)
        capture("alice_own_record", "GET", "/records/alice-note", response, 200, alice_auth)
        _expect(response.body.get("value") == "ALICE_PRIVATE_FIXTURE", f"{variant}:alice_own_body")
        response = probe.request("GET", "/records/bob-note", sid=alice_auth)
        capture("alice_reads_bob_record", "GET", "/records/bob-note", response, 200 if expected_weak else 403, alice_auth)
        _expect((response.body.get("value") == "BOB_PRIVATE_FIXTURE") == expected_weak, f"{variant}:alice_cross_account_body")

        bob_start = probe.request("GET", "/start")
        capture("bob_anonymous_start", "GET", "/start", bob_start, 200)
        bob_pre = bob_start.set_sid
        _expect(bool(bob_pre) and bob_pre != alice_pre, f"{variant}:bob_pre_id")
        bob_login = probe.request("POST", "/login", sid=bob_pre, form={"username": "bob", "password": "bob-lab-secret"})
        capture("bob_login", "POST", "/login", bob_login, 200, bob_pre)
        bob_auth = bob_login.set_sid
        _expect(bool(bob_auth) and bob_auth != alice_auth, f"{variant}:bob_auth_id")
        _expect((bob_auth == bob_pre) == expected_weak, f"{variant}:bob_rotation")
        response = probe.request("GET", "/records/bob-note", sid=bob_auth)
        capture("bob_own_record", "GET", "/records/bob-note", response, 200, bob_auth)
        _expect(response.body.get("value") == "BOB_PRIVATE_FIXTURE", f"{variant}:bob_own_body")
        response = probe.request("GET", "/records/alice-note", sid=bob_auth)
        capture("bob_reads_alice_record", "GET", "/records/alice-note", response, 200 if expected_weak else 403, bob_auth)
        _expect((response.body.get("value") == "ALICE_PRIVATE_FIXTURE") == expected_weak, f"{variant}:bob_cross_account_body")

        logout = probe.request("POST", "/logout", sid=alice_auth)
        capture("alice_logout", "POST", "/logout", logout, 204, alice_auth)
        _expect(logout.cookie_cleared, f"{variant}:cookie_not_cleared")
        response = probe.request("GET", "/me", sid=alice_auth)
        capture("alice_old_id_replay_after_logout", "GET", "/me", response, 200 if expected_weak else 401, alice_auth)
        _expect((response.body.get("account") == "alice") == expected_weak, f"{variant}:logout_replay_body")
        response = probe.request("GET", "/records/alice-note", sid=alice_auth)
        capture("alice_record_replay_after_logout", "GET", "/records/alice-note", response, 200 if expected_weak else 401, alice_auth)
        _expect((response.body.get("value") == "ALICE_PRIVATE_FIXTURE") == expected_weak, f"{variant}:logout_record_body")
        response = probe.request("GET", "/me", sid=bob_auth)
        capture("bob_session_unaffected", "GET", "/me", response, 200, bob_auth)
        _expect(response.body.get("account") == "bob", f"{variant}:bob_unaffected_body")

        _expect(len(matrix) == len(lab.requests) == 18, f"{variant}:matrix_request_count")
        return {
            "variant": variant,
            "outcome": "DEMONSTRATED_INTENTIONAL_WEAKNESS" if expected_weak else "PASS_FIXED_CONTROLS",
            "bind_address": "127.0.0.1",
            "port": lab.port,
            "pre_auth_sid_fingerprint": fingerprint(alice_pre),
            "post_auth_sid_fingerprint": fingerprint(alice_auth),
            "session_id_rotated_on_login": alice_auth != alice_pre,
            "old_session_rejected_after_logout": not expected_weak,
            "cross_account_read_denied": not expected_weak,
            "request_matrix": matrix,
            "server_request_log": list(lab.requests),
            "checked_rows": len(matrix),
        }


def run_experiment() -> dict[str, object]:
    weak = _run_variant("weak_baseline")
    fixed = _run_variant("fixed")
    return {
        "schema": "web-session-dast-review-local-matrix-v1",
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "project_version": "0.1.0",
        "python_version": platform.python_version(),
        "network_scope": "Self-owned HTTP servers bound only to 127.0.0.1 on ephemeral ports; no external target scanning",
        "synthetic_accounts": ["alice", "bob"],
        "raw_session_ids_or_passwords_logged": False,
        "variants": [weak, fixed],
        "checked_rows": weak["checked_rows"] + fixed["checked_rows"],
        "upstream_vulnerability_claim": False,
        "cvp_qualification": "OPEN",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run only the self-owned loopback session lifecycle matrix")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = run_experiment()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": "PASS_LOCAL_MATRIX", "rows": receipt["checked_rows"], "receipt": str(args.output)}))


if __name__ == "__main__":
    main()
