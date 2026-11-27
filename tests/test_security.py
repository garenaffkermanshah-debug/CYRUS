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


    def test_readiness_succeeds_when_supabase_auth_is_reachable(self):
        from unittest.mock import Mock, patch

        previous_url, previous_key = cyrus.URL, cyrus.KEY
        cyrus.URL, cyrus.KEY = "https://project.example", "test-public-key"
        try:
            backend = Mock(ok=True, status_code=200)
            with patch.object(cyrus.requests, "get", return_value=backend) as get:
                response = self.client.get("/readyz")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["status"], "ready")
            self.assertIn("no-store", response.headers.get("Cache-Control", ""))
            get.assert_called_once_with(
                "https://project.example/auth/v1/settings",
                headers={"apikey": "test-public-key", "Accept": "application/json"},
                timeout=5,
            )
            self.assertNotIn("test-public-key", response.get_data(as_text=True))
        finally:
            cyrus.URL, cyrus.KEY = previous_url, previous_key

    def test_readiness_fails_when_supabase_auth_returns_error(self):
        from unittest.mock import Mock, patch

        previous_url, previous_key = cyrus.URL, cyrus.KEY
        cyrus.URL, cyrus.KEY = "https://project.example", "test-public-key"
        try:
            with patch.object(cyrus.requests, "get", return_value=Mock(ok=False)):
                response = self.client.get("/readyz")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json["status"], "not_ready")
            self.assertEqual(response.json["reason"], "backend")
        finally:
            cyrus.URL, cyrus.KEY = previous_url, previous_key

    def test_readiness_fails_when_supabase_auth_times_out(self):
        from unittest.mock import patch
        import requests

        previous_url, previous_key = cyrus.URL, cyrus.KEY
        cyrus.URL, cyrus.KEY = "https://project.example", "test-public-key"
        try:
            with patch.object(cyrus.requests, "get", side_effect=requests.Timeout):
                response = self.client.get("/readyz")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json["status"], "not_ready")
            self.assertEqual(response.json["reason"], "backend")
        finally:
            cyrus.URL, cyrus.KEY = previous_url, previous_key

    def test_login_page_issues_csrf_token_and_accepts_valid_form(self):
        page = self.client.get("/login")
        self.assertEqual(page.status_code, 200)
        self.assertIn("csrf_token", page.get_data(as_text=True))
        with self.client.session_transaction() as state:
            token = state.get("csrf_token")
        self.assertTrue(token)
        response = self.client.post(
            "/login",
            data={"csrf_token": token, "email": "pilot@example.com"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login/password")

    def test_pwa_manifest_points_to_existing_app_icon(self):
        manifest_response = self.client.get("/manifest.webmanifest")
        self.assertEqual(manifest_response.status_code, 200)
        manifest = manifest_response.get_json()
        self.assertEqual(manifest["start_url"], "/home")
        icon_response = self.client.get(manifest["icons"][0]["src"])
        self.assertEqual(icon_response.status_code, 200)
        self.assertEqual(icon_response.mimetype, "image/svg+xml")

    def test_service_worker_cache_assets_exist_and_scope_is_root(self):
        response = self.client.get("/service-worker.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn("no-cache", response.headers.get("Cache-Control", ""))
        self.assertEqual(response.headers.get("Service-Worker-Allowed"), "/")
        worker = response.get_data(as_text=True)
        self.assertIn("const CACHE='cyrus-static-v1'", worker)
        for asset in (
            "/static/cyrus-app-icon.svg",
            "/static/cyrus-cylinder.jpg",
            "/static/cyrus-tomb.jpg",
        ):
            with self.subTest(asset=asset):
                self.assertIn(asset, worker)
                asset_response = self.client.get(asset)
                self.assertEqual(asset_response.status_code, 200)

    def test_media_signature_validation_accepts_matching_file_headers(self):
        valid_samples = [
            ("image/jpeg", b"\xff\xd8\xffsample"),
            ("image/png", b"\x89PNG\r\n\x1a\nsample"),
            ("image/gif", b"GIF89asample"),
            ("video/mp4", b"\x00\x00\x00\x18ftypisom"),
            ("audio/ogg", b"OggSsample"),
            ("application/pdf", b"%PDF-1.7 sample"),
            ("text/plain", "متن آزمایشی".encode("utf-8")),
        ]
        for mime, payload in valid_samples:
            with self.subTest(mime=mime):
                self.assertTrue(cyrus.cyrus_media_signature_valid(mime, payload))

    def test_media_signature_validation_rejects_mismatched_and_empty_files(self):
        invalid_samples = [
            ("image/jpeg", b"not-a-jpeg"),
            ("image/png", b"\x89PNG-invalid"),
            ("video/mp4", b"plain text pretending to be video"),
            ("application/pdf", b"<html>not a PDF</html>"),
            ("text/plain", b"binary\x00payload"),
            ("image/gif", b""),
        ]
        for mime, payload in invalid_samples:
            with self.subTest(mime=mime, payload=payload):
                self.assertFalse(cyrus.cyrus_media_signature_valid(mime, payload))

    def test_achaemenid_background_asset_is_available(self):
        response = self.client.get("/static/cyrus-tomb.jpg")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.mimetype.startswith("image/"))
        with open(cyrus.__file__, encoding="utf-8") as source:
            app_source = source.read()
        self.assertIn("/static/cyrus-tomb.jpg", app_source)
        self.assertNotIn("cyrus-iran-panorama.jpg", app_source)

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
