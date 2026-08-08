import json
import os
import time
import unittest

os.environ["SECRET_KEY"] = "test-only-high-entropy-signing-key-32-bytes"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

import jwt

from config import db, limiter, vuln_app
from models.user_model import User


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        self.app = vuln_app.app
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            User.init_db_users()
        limiter.reset()

    def login(self, username="name1", password="pass1"):
        return self.client.post(
            "/users/v1/login",
            json={"username": username, "password": password},
        )

    def token(self, username="name1", password="pass1"):
        response = self.login(username, password)
        self.assertEqual(response.status_code, 200)
        return response.get_json()["auth_token"]

    @staticmethod
    def bearer(token):
        return {"Authorization": f"Bearer {token}"}

    def test_legacy_jwt_secret_cannot_forge_admin_token(self):
        forged = jwt.encode(
            {"sub": "admin", "iat": int(time.time()), "exp": int(time.time()) + 60},
            "random",
            algorithm="HS256",
        )
        response = self.client.get("/me", headers=self.bearer(forged))
        self.assertEqual(response.status_code, 401)

        unsigned = jwt.encode(
            {"sub": "admin", "iat": int(time.time()), "exp": int(time.time()) + 60},
            key=None,
            algorithm="none",
        )
        response = self.client.get("/me", headers=self.bearer(unsigned))
        self.assertEqual(response.status_code, 401)

    def test_debug_requires_admin_and_never_returns_passwords(self):
        anonymous = self.client.get("/users/v1/_debug")
        self.assertEqual(anonymous.status_code, 401)

        ordinary = self.client.get(
            "/users/v1/_debug", headers=self.bearer(self.token())
        )
        self.assertEqual(ordinary.status_code, 403)

        admin = self.client.get(
            "/users/v1/_debug", headers=self.bearer(self.token("admin", "pass1"))
        )
        self.assertEqual(admin.status_code, 200)
        payload = admin.get_json()
        self.assertTrue(payload["users"])
        self.assertTrue(all("password" not in user for user in payload["users"]))

    def test_registration_ignores_admin_mass_assignment(self):
        accepted = self.client.post(
            "/users/v1/register",
            json={
                "username": "mallory",
                "password": "safe-pass",
                "email": "mallory@example.com",
                "admin": True,
            },
        )
        self.assertEqual(accepted.status_code, 200)
        with self.app.app_context():
            self.assertFalse(User.query.filter_by(username="mallory").one().admin)

    def test_user_lookup_does_not_execute_sql_syntax(self):
        exploit = self.client.get(
            "/users/v1/anythingRandom%27%20or%20%271%27=%271"
        )
        self.assertEqual(exploit.status_code, 404)

        legitimate = self.client.get("/users/v1/name1")
        self.assertEqual(legitimate.status_code, 200)
        self.assertEqual(json.loads(legitimate.get_data(as_text=True))["username"], "name1")

        quoted_username = 'quoted"name'
        self.client.post(
            "/users/v1/register",
            json={
                "username": quoted_username,
                "password": "safe-pass",
                "email": "quoted@example.com",
            },
        )
        encoded = self.client.get("/users/v1/quoted%22name")
        self.assertEqual(encoded.status_code, 200)
        self.assertEqual(encoded.get_json()["username"], quoted_username)

    def test_password_update_is_self_only_and_remains_usable(self):
        name1_token = self.token()
        denied = self.client.put(
            "/users/v1/admin/password",
            headers=self.bearer(name1_token),
            json={"password": "hijacked"},
        )
        self.assertEqual(denied.status_code, 403)
        self.assertIn("auth_token", self.login("admin", "pass1").get_json())

        changed = self.client.put(
            "/users/v1/name1/password",
            headers=self.bearer(name1_token),
            json={"password": "new-name1-pass"},
        )
        self.assertEqual(changed.status_code, 204)
        self.assertNotIn("auth_token", self.login("name1", "pass1").get_json())
        self.assertIn("auth_token", self.login("name1", "new-name1-pass").get_json())

    def test_book_secret_is_visible_only_to_owner(self):
        with self.app.app_context():
            name2_book = User.query.filter_by(username="name2").one().books[0].book_title

        denied = self.client.get(
            f"/books/v1/{name2_book}", headers=self.bearer(self.token("name1", "pass1"))
        )
        self.assertEqual(denied.status_code, 404)

        allowed = self.client.get(
            f"/books/v1/{name2_book}", headers=self.bearer(self.token("name2", "pass2"))
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.get_json()["owner"], "name2")

    def test_email_validation_bounds_work_and_preserves_valid_email(self):
        token = self.token()
        oversized = self.client.put(
            "/users/v1/name1/email",
            headers=self.bearer(token),
            json={"email": "a" * 10000 + "!"},
        )
        self.assertEqual(oversized.status_code, 400)

        legitimate = self.client.put(
            "/users/v1/name1/email",
            headers=self.bearer(token),
            json={"email": "name1+alerts@example.com"},
        )
        self.assertEqual(legitimate.status_code, 204)

    def test_login_failure_does_not_enumerate_users(self):
        existing = self.login("name1", "wrong-password")
        missing = self.login("does-not-exist", "wrong-password")
        self.assertEqual(existing.status_code, missing.status_code)
        self.assertEqual(existing.get_json(), missing.get_json())

    def test_login_is_rate_limited_per_client_and_account(self):
        responses = [self.login("name1", "wrong-password") for _ in range(11)]
        self.assertTrue(all(response.status_code == 200 for response in responses[:10]))
        self.assertEqual(responses[-1].status_code, 429)

    def test_global_rate_limit_bounds_public_endpoints(self):
        responses = [self.client.get("/") for _ in range(61)]
        self.assertTrue(all(response.status_code == 200 for response in responses[:60]))
        self.assertEqual(responses[-1].status_code, 429)

    def test_request_size_limit_and_security_headers(self):
        oversized = self.client.post(
            "/users/v1/register",
            data=b"x" * (16 * 1024 + 1),
            content_type="application/json",
        )
        self.assertEqual(oversized.status_code, 413)

        response = self.client.get("/")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")

    def test_malformed_json_is_rejected_without_internal_error(self):
        registration = self.client.post(
            "/users/v1/register", data=b"null", content_type="application/json"
        )
        self.assertEqual(registration.status_code, 400)

        book = self.client.post(
            "/books/v1",
            data=b"[]",
            content_type="application/json",
            headers=self.bearer(self.token()),
        )
        self.assertEqual(book.status_code, 400)

    def test_database_bootstrap_is_idempotent_and_non_destructive(self):
        with self.app.app_context():
            db.drop_all()

        first = self.client.get("/createdb")
        self.assertEqual(first.status_code, 200)
        with self.app.app_context():
            self.assertEqual(User.query.count(), 3)
            User.register_user("persistent", "persist-pass", "persist@example.com")

        second = self.client.get("/createdb")
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.get_json(), first.get_json())
        with self.app.app_context():
            self.assertEqual(User.query.count(), 4)
            self.assertIsNotNone(User.query.filter_by(username="persistent").first())

    def test_legacy_plaintext_password_is_upgraded_on_login(self):
        with self.app.app_context():
            user = User.query.filter_by(username="name1").one()
            user.password = "legacy-pass"
            db.session.commit()

        self.assertIn("auth_token", self.login("name1", "legacy-pass").get_json())
        with self.app.app_context():
            user = User.query.filter_by(username="name1").one()
            self.assertNotEqual(user.password, "legacy-pass")
            self.assertTrue(user.check_password("legacy-pass"))

    def test_passwords_are_hashed_and_flask_debug_is_disabled(self):
        with self.app.app_context():
            user = User.query.filter_by(username="name1").one()
            self.assertNotEqual(user.password, "pass1")
            self.assertTrue(user.check_password("pass1"))
        self.assertFalse(self.app.debug)


if __name__ == "__main__":
    unittest.main()
