"""Independent HTTP-level checks of the two intentionally different variants."""

from __future__ import annotations

import unittest

from web_session_dast_review.http_probe import LoopbackProbe
from web_session_dast_review.server import SessionLab


def _begin_and_login(probe: LoopbackProbe, account: str) -> tuple[str, str]:
    before = probe.request("GET", "/start")
    assert before.status == 200 and before.set_sid
    after = probe.request(
        "POST", "/login", sid=before.set_sid,
        form={"username": account, "password": f"{account}-lab-secret"},
    )
    assert after.status == 200 and after.set_sid
    return before.set_sid, after.set_sid


class SessionHttpTests(unittest.TestCase):
    def test_fixed_login_rotates_id_and_rejects_old_pre_auth_id(self) -> None:
        with SessionLab("fixed") as lab:
            probe = LoopbackProbe(lab.port)
            before, after = _begin_and_login(probe, "alice")
            self.assertNotEqual(before, after)
            self.assertEqual(probe.request("GET", "/me", sid=before).status, 401)
            self.assertEqual(probe.request("GET", "/me", sid=after).body, {"account": "alice"})

    def test_weak_baseline_retains_known_pre_auth_id(self) -> None:
        with SessionLab("weak_baseline") as lab:
            probe = LoopbackProbe(lab.port)
            before, after = _begin_and_login(probe, "alice")
            self.assertEqual(before, after)
            self.assertEqual(probe.request("GET", "/me", sid=before).body, {"account": "alice"})

    def test_fixed_logout_revokes_server_session_not_just_cookie(self) -> None:
        with SessionLab("fixed") as lab:
            probe = LoopbackProbe(lab.port)
            _, sid = _begin_and_login(probe, "alice")
            logout = probe.request("POST", "/logout", sid=sid)
            self.assertEqual(logout.status, 204)
            self.assertTrue(logout.cookie_cleared)
            self.assertEqual(probe.request("GET", "/me", sid=sid).status, 401)
            self.assertEqual(probe.request("GET", "/records/alice-note", sid=sid).status, 401)

    def test_weak_logout_only_clears_cookie_and_replay_still_works(self) -> None:
        with SessionLab("weak_baseline") as lab:
            probe = LoopbackProbe(lab.port)
            _, sid = _begin_and_login(probe, "alice")
            self.assertTrue(probe.request("POST", "/logout", sid=sid).cookie_cleared)
            self.assertEqual(probe.request("GET", "/me", sid=sid).status, 200)
            self.assertEqual(probe.request("GET", "/records/alice-note", sid=sid).body["value"], "ALICE_PRIVATE_FIXTURE")

    def test_fixed_owner_boundary_denies_both_cross_account_reads(self) -> None:
        with SessionLab("fixed") as lab:
            probe = LoopbackProbe(lab.port)
            _, alice = _begin_and_login(probe, "alice")
            _, bob = _begin_and_login(probe, "bob")
            for sid, target in ((alice, "bob-note"), (bob, "alice-note")):
                response = probe.request("GET", f"/records/{target}", sid=sid)
                self.assertEqual(response.status, 403)
                self.assertNotIn("value", response.body)

    def test_weak_baseline_exposes_both_cross_account_records(self) -> None:
        with SessionLab("weak_baseline") as lab:
            probe = LoopbackProbe(lab.port)
            _, alice = _begin_and_login(probe, "alice")
            _, bob = _begin_and_login(probe, "bob")
            self.assertEqual(probe.request("GET", "/records/bob-note", sid=alice).body["value"], "BOB_PRIVATE_FIXTURE")
            self.assertEqual(probe.request("GET", "/records/alice-note", sid=bob).body["value"], "ALICE_PRIVATE_FIXTURE")

    def test_fixed_owner_can_read_own_record_and_identity(self) -> None:
        with SessionLab("fixed") as lab:
            probe = LoopbackProbe(lab.port)
            for account in ("alice", "bob"):
                _, sid = _begin_and_login(probe, account)
                self.assertEqual(probe.request("GET", "/me", sid=sid).body["account"], account)
                own = probe.request("GET", f"/records/{account}-note", sid=sid)
                self.assertEqual((own.status, own.body["owner"]), (200, account))

    def test_unknown_client_chosen_id_is_not_adopted(self) -> None:
        with SessionLab("fixed") as lab:
            probe = LoopbackProbe(lab.port)
            chosen = "chosen-but-never-issued"
            self.assertEqual(probe.request("GET", "/me", sid=chosen).status, 401)
            login = probe.request("POST", "/login", sid=chosen, form={"username": "alice", "password": "alice-lab-secret"})
            self.assertEqual(login.status, 400)
            start = probe.request("GET", "/start", sid=chosen)
            self.assertEqual(start.status, 200)
            self.assertNotEqual(start.set_sid, chosen)

    def test_bad_password_does_not_bind_anonymous_session(self) -> None:
        with SessionLab("fixed") as lab:
            probe = LoopbackProbe(lab.port)
            before = probe.request("GET", "/start").set_sid
            self.assertIsNotNone(before)
            bad = probe.request("POST", "/login", sid=before, form={"username": "alice", "password": "wrong"})
            self.assertEqual(bad.status, 401)
            self.assertEqual(probe.request("GET", "/me", sid=before).status, 401)

    def test_one_account_logout_does_not_invalidate_other_account(self) -> None:
        with SessionLab("fixed") as lab:
            probe = LoopbackProbe(lab.port)
            _, alice = _begin_and_login(probe, "alice")
            _, bob = _begin_and_login(probe, "bob")
            probe.request("POST", "/logout", sid=alice)
            self.assertEqual(probe.request("GET", "/me", sid=alice).status, 401)
            self.assertEqual(probe.request("GET", "/me", sid=bob).body["account"], "bob")

    def test_cookie_and_response_metadata_for_loopback_only(self) -> None:
        with SessionLab("fixed") as lab:
            probe = LoopbackProbe(lab.port)
            start = probe.request("GET", "/start")
            self.assertEqual(start.cache_control, "no-store")
            self.assertIn("HttpOnly", start.set_cookie_header)
            self.assertIn("SameSite=Lax", start.set_cookie_header)
            self.assertNotIn(start.set_sid, str(start.body))

    def test_rejects_malformed_login_form_without_authentication(self) -> None:
        with SessionLab("fixed") as lab:
            probe = LoopbackProbe(lab.port)
            before = probe.request("GET", "/start").set_sid
            self.assertIsNotNone(before)
            bad = probe.request("POST", "/login", sid=before, form={"username": "alice"})
            self.assertEqual(bad.status, 400)
            self.assertEqual(probe.request("GET", "/me", sid=before).status, 401)


if __name__ == "__main__":
    unittest.main()
