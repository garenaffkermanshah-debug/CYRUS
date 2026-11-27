"""Regression tests for CYRUS's browser-facing security boundaries.

These tests do not contact Supabase and are safe to run in CI.
"""
import os
import unittest

# Keep application import deterministic and prevent any real backend request.
os.environ["SECRET_KEY"] = "cyrus-test-only-secret-key-not-for-production"
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_KEY"] = ""

import app as cyrus


class CyrusSecurityTests(unittest.TestCase):
    def setUp(self):
        cyrus.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = cyrus.app.test_client()

    def test_liveness_probe_is_public_and_non_cacheable(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "alive")
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))

    def test_readiness_fails_closed_without_backend_configuration(self):
        response = self.client.get("/readyz")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json["status"], "not_ready")
        self.assertNotIn("SUPABASE_KEY", response.get_data(as_text=True))

    def test_security_headers_are_present(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(
            response.headers.get("Referrer-Policy"),
            "strict-origin-when-cross-origin",
        )

    def test_browser_form_without_csrf_token_is_rejected(self):
        response = self.client.post("/logout", data={"unused": "value"})
        self.assertEqual(response.status_code, 403)

    def test_browser_form_with_valid_csrf_token_is_accepted(self):
        with self.client.session_transaction() as state:
            state["csrf_token"] = "test-csrf-token"
        response = self.client.post(
            "/logout", data={"csrf_token": "test-csrf-token"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_cross_site_state_change_is_rejected(self):
        response = self.client.post(
            "/logout",
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        self.assertEqual(response.status_code, 403)

    def test_foreign_origin_state_change_is_rejected(self):
        response = self.client.post(
            "/logout",
            headers={"Origin": "https://attacker.example"},
        )
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
