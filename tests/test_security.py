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

    def test_new_supabase_secret_key_is_not_sent_as_bearer_jwt(self):
        previous = cyrus.ADMIN_KEY
        cyrus.ADMIN_KEY = "sb_secret_test_only"
        try:
            headers = cyrus.cyrus_security_headers()
            self.assertEqual(headers["apikey"], "sb_secret_test_only")
            self.assertNotIn("Authorization", headers)
            self.assertEqual(headers["Content-Type"], "application/json")
        finally:
            cyrus.ADMIN_KEY = previous

    def test_legacy_service_role_key_keeps_bearer_compatibility(self):
        previous = cyrus.ADMIN_KEY
        cyrus.ADMIN_KEY = "legacy-service-role-jwt"
        try:
            headers = cyrus.cyrus_security_headers()
            self.assertEqual(headers["apikey"], "legacy-service-role-jwt")
            self.assertEqual(headers["Authorization"], "Bearer legacy-service-role-jwt")
        finally:
            cyrus.ADMIN_KEY = previous

    def test_liveness_probe_is_public_and_non_cacheable(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "alive")
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))

    def test_readiness_fails_closed_without_backend_configuration(self):
        previous = (cyrus.URL, cyrus.KEY, cyrus.ADMIN_KEY)
        cyrus.URL, cyrus.KEY, cyrus.ADMIN_KEY = "", "", ""
        try:
            response = self.client.get("/readyz")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json["status"], "not_ready")
            self.assertNotIn("SUPABASE_KEY", response.get_data(as_text=True))
        finally:
            cyrus.URL, cyrus.KEY, cyrus.ADMIN_KEY = previous

    def test_readiness_succeeds_when_supabase_auth_is_reachable(self):
        from unittest.mock import Mock, patch

        previous = (cyrus.URL, cyrus.KEY, cyrus.ADMIN_KEY)
        cyrus.URL, cyrus.KEY, cyrus.ADMIN_KEY = (
            "https://project.example", "test-public-key", "test-admin-key"
        )
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
            cyrus.URL, cyrus.KEY, cyrus.ADMIN_KEY = previous

    def test_readiness_fails_when_supabase_auth_returns_error(self):
        from unittest.mock import Mock, patch

        previous = (cyrus.URL, cyrus.KEY, cyrus.ADMIN_KEY)
        cyrus.URL, cyrus.KEY, cyrus.ADMIN_KEY = (
            "https://project.example", "test-public-key", "test-admin-key"
        )
        try:
            with patch.object(cyrus.requests, "get", return_value=Mock(ok=False)):
                response = self.client.get("/readyz")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json["status"], "not_ready")
            self.assertEqual(response.json["reason"], "backend")
        finally:
            cyrus.URL, cyrus.KEY, cyrus.ADMIN_KEY = previous

    def test_readiness_fails_when_supabase_auth_times_out(self):
        from unittest.mock import patch
        import requests

        previous = (cyrus.URL, cyrus.KEY, cyrus.ADMIN_KEY)
        cyrus.URL, cyrus.KEY, cyrus.ADMIN_KEY = (
            "https://project.example", "test-public-key", "test-admin-key"
        )
        try:
            with patch.object(cyrus.requests, "get", side_effect=requests.Timeout):
                response = self.client.get("/readyz")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json["status"], "not_ready")
            self.assertEqual(response.json["reason"], "backend")
        finally:
            cyrus.URL, cyrus.KEY, cyrus.ADMIN_KEY = previous

    def test_expired_session_refreshes_and_rotates_tokens(self):
        from unittest.mock import Mock, patch

        with self.client.session_transaction() as state:
            state.update(access_token="old-access", refresh_token="old-refresh",
                         token_expires_at=0)
        backend = Mock(status_code=200)
        backend.json.return_value = {
            "access_token": "new-access", "refresh_token": "new-refresh",
            "expires_in": 1800,
        }
        with patch.object(cyrus.requests, "post", return_value=backend) as post:
            response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        post.assert_called_once()
        with self.client.session_transaction() as state:
            self.assertEqual(state["access_token"], "new-access")
            self.assertEqual(state["refresh_token"], "new-refresh")
            self.assertGreater(state["token_expires_at"], 0)
            self.assertTrue(state.permanent)

    def test_revoked_refresh_token_clears_authentication(self):
        from unittest.mock import Mock, patch

        with self.client.session_transaction() as state:
            state.update(access_token="old-access", refresh_token="revoked",
                         token_expires_at=0, user_id="user-123")
            state["csrf_token"] = "keep-csrf"
        backend = Mock(status_code=400)
        backend.json.return_value = {"error": "invalid_grant"}
        with patch.object(cyrus.requests, "post", return_value=backend):
            response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as state:
            self.assertNotIn("access_token", state)
            self.assertNotIn("refresh_token", state)
            self.assertNotIn("user_id", state)
            self.assertEqual(state.get("csrf_token"), "keep-csrf")

    def test_expired_session_without_refresh_token_is_cleared(self):
        with self.client.session_transaction() as state:
            state.update(access_token="stale-access", token_expires_at=0,
                         user_id="user-123")
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as state:
            self.assertNotIn("access_token", state)
            self.assertNotIn("user_id", state)

    def test_temporary_refresh_failure_preserves_session_for_retry(self):
        from unittest.mock import Mock, patch

        with self.client.session_transaction() as state:
            state.update(access_token="old-access", refresh_token="old-refresh",
                         token_expires_at=0, user_id="user-123")
        backend = Mock(status_code=503)
        backend.json.return_value = {"message": "temporarily unavailable"}
        with patch.object(cyrus.requests, "post", return_value=backend):
            response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as state:
            self.assertEqual(state.get("access_token"), "old-access")
            self.assertEqual(state.get("refresh_token"), "old-refresh")
            self.assertGreater(state["token_expires_at"], 0)

    def test_login_page_issues_csrf_token_and_accepts_valid_form(self):
        from unittest.mock import patch

        page = self.client.get("/login")
        self.assertEqual(page.status_code, 200)
        self.assertIn("csrf_token", page.get_data(as_text=True))
        with self.client.session_transaction() as state:
            token = state.get("csrf_token")
        self.assertTrue(token)
        existing = {"id": "user-123", "email_confirmed_at": "2026-01-01T00:00:00Z"}
        with patch.object(cyrus, "auth_find_user_by_email", return_value=(existing, None)), \
             patch.object(cyrus, "cyrus_get_account_security", return_value=(None, None)), \
             patch.object(cyrus, "auth_request", return_value=(200, {})):
            response = self.client.post(
                "/login",
                data={"csrf_token": token, "email": "pilot@example.com"},
            )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/verify-email")
        with self.client.session_transaction() as state:
            self.assertEqual(state.get("cyrus_pending_email"), "pilot@example.com")
            self.assertEqual(state.get("cyrus_pending_flow"), "login")

    def test_expired_otp_error_explains_last_code_and_validity(self):
        from unittest.mock import patch

        with self.client.session_transaction() as state:
            state.update(
                cyrus_pending_email="pilot@example.com",
                cyrus_pending_flow="login",
                csrf_token="test-csrf-token",
            )
        with patch.object(cyrus, "auth_request", return_value=(403, {"error_code": "otp_expired"})):
            response = self.client.post(
                "/verify-email",
                data={"csrf_token": "test-csrf-token", "token": "123456"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("۶۰۰ ثانیه", response.get_data(as_text=True))
        self.assertIn("آخرین کد ایمیل", response.get_data(as_text=True))

    def test_pwa_manifest_points_to_existing_app_icon(self):
        manifest_response = self.client.get("/manifest.webmanifest")
        self.assertEqual(manifest_response.status_code, 200)
        manifest = manifest_response.get_json()
        self.assertEqual(manifest["start_url"], "/home")
        icon_response = self.client.get(manifest["icons"][0]["src"])
        self.assertEqual(icon_response.status_code, 200)
        self.assertEqual(icon_response.mimetype, "image/webp")

    def test_service_worker_cache_assets_exist_and_scope_is_root(self):
        response = self.client.get("/service-worker.js")
        self.assertEqual(response.status_code, 200)
        self.assertIn("no-cache", response.headers.get("Cache-Control", ""))
        self.assertEqual(response.headers.get("Service-Worker-Allowed"), "/")
        worker = response.get_data(as_text=True)
        self.assertIn("const CACHE='cyrus-static-v2'", worker)
        for asset in (
            "/static/cyrus-app-icon.webp",
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
