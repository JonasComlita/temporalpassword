from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from apps.users.models import TemporalPassword

from .serializers import TemporalPasswordRegisterSerializer
from .temporal import encode_temporal_combined_secret

User = get_user_model()
TEST_CACHES = {
    "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}
}
TEST_PASSWORD_HASHERS = [
    "apps.authentication.hashers.PepperedPBKDF2PasswordHasher",
]
TEST_AUTH_PASSWORD_PEPPER = "test-pepper-for-auth"


@override_settings(
    CACHES=TEST_CACHES,
    PASSWORD_HASHERS=TEST_PASSWORD_HASHERS,
    AUTH_PASSWORD_PEPPER=TEST_AUTH_PASSWORD_PEPPER,
    AUTH_PASSWORD_PEPPER_REQUIRED=True,
    AUTH_PBKDF2_ITERATIONS=12000,
)
class TemporalPasswordAuthTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.login_url = reverse("authentication:temporal_login")
        self.password_groups = ["Ab", "9$", "xY", "2#", "Qq", "7!", "Lm", "5%"]
        self.time_intervals = [12, 8, 5, 9, 7, 4, 11, 6]

    def _create_temporal_user(self, username, *, is_verified=True, is_active=True):
        user = User.objects.create_user(
            username=username,
            email=f"{username}@example.com",
            password=None,
            is_verified=is_verified,
            is_active=is_active,
        )
        user.set_unusable_password()
        user.save(update_fields=["password"])

        TemporalPassword.objects.create(
            user=user,
            combined_secret_hash=make_password(
                encode_temporal_combined_secret(self.password_groups, self.time_intervals)
            ),
        )
        return user

    def _valid_login_payload(self, username):
        return {
            "username": username,
            "password_groups": [
                {"text": group, "time": interval}
                for group, interval in zip(self.password_groups, self.time_intervals)
            ],
        }

    def test_temporal_login_requires_verified_email(self):
        user = self._create_temporal_user("temporal_unverified", is_verified=False)

        response = self.client.post(self.login_url, self._valid_login_payload(user.username), format="json")

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("code"), "email_not_verified")

    def test_temporal_login_locks_after_failed_attempts(self):
        user = self._create_temporal_user("temporal_lock")
        bad_payload = self._valid_login_payload(user.username)
        bad_payload["password_groups"][0]["text"] = "WRONG"

        for _ in range(4):
            response = self.client.post(self.login_url, bad_payload, format="json")
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
            self.assertEqual(response.data.get("code"), "invalid_credentials")

        response = self.client.post(self.login_url, bad_payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_423_LOCKED)
        self.assertEqual(response.data.get("code"), "account_locked")

        user.refresh_from_db()
        self.assertEqual(user.failed_login_attempts, 5)
        self.assertTrue(user.locked_until and user.locked_until > timezone.now())

    def test_temporal_login_rejects_locked_account_with_valid_credentials(self):
        user = self._create_temporal_user("temporal_already_locked")
        user.failed_login_attempts = 5
        user.locked_until = timezone.now() + timedelta(minutes=10)
        user.save(update_fields=["failed_login_attempts", "locked_until"])

        response = self.client.post(self.login_url, self._valid_login_payload(user.username), format="json")

        self.assertEqual(response.status_code, status.HTTP_423_LOCKED)
        self.assertEqual(response.data.get("code"), "account_locked")

    def test_temporal_login_invalid_group_payload_returns_400(self):
        payload = {
            "username": "whoever",
            "password_groups": [{"text": "AA"} for _ in range(8)],
        }

        response = self.client.post(self.login_url, payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password_groups", response.data)

    def test_temporal_login_resets_failed_attempts_after_success(self):
        user = self._create_temporal_user("temporal_resets")
        user.failed_login_attempts = 3
        user.locked_until = None
        user.save(update_fields=["failed_login_attempts", "locked_until"])

        response = self.client.post(self.login_url, self._valid_login_payload(user.username), format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertEqual(user.failed_login_attempts, 0)
        self.assertIsNone(user.locked_until)

    def test_regular_password_uses_peppered_hasher(self):
        user = User.objects.create_user(
            username="regular_user",
            email="regular_user@example.com",
            password="RegularPassword123!",
            is_verified=True,
        )

        self.assertTrue(user.password.startswith("peppered_pbkdf2_sha256$"))
        self.assertTrue(user.check_password("RegularPassword123!"))

    def test_temporal_registration_uses_peppered_hasher(self):
        serializer = TemporalPasswordRegisterSerializer(
            data={
                "username": "temporal_new",
                "email": "temporal_new@example.com",
                "password_groups": self.password_groups,
                "time_intervals": self.time_intervals,
            }
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        user = serializer.save()
        temporal = TemporalPassword.objects.get(user=user)

        self.assertTrue(temporal.combined_secret_hash.startswith("peppered_pbkdf2_sha256$"))
