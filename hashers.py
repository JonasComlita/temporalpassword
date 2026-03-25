import os

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.contrib.auth.hashers import Argon2PasswordHasher, PBKDF2PasswordHasher


def get_password_pepper():
    pepper = getattr(settings, "AUTH_PASSWORD_PEPPER", None) or os.getenv("AUTH_PASSWORD_PEPPER")
    if pepper:
        return pepper

    if getattr(settings, "DEBUG", False):
        # Debug-only fallback to keep local dev usable without external secret wiring.
        return f"debug-pepper::{settings.SECRET_KEY}"

    raise ImproperlyConfigured(
        "AUTH_PASSWORD_PEPPER is required in non-debug environments. "
        "Inject it from KMS/HSM/secret manager at runtime."
    )


class _PepperedHasherMixin:
    pepper_separator = "::"

    def _pepper(self, password):
        if password is None:
            return None
        return f"{get_password_pepper()}{self.pepper_separator}{password}"


class PepperedArgon2PasswordHasher(_PepperedHasherMixin, Argon2PasswordHasher):
    algorithm = "peppered_argon2"

    def __init__(self):
        super().__init__()
        self.time_cost = int(getattr(settings, "AUTH_ARGON2_TIME_COST", self.time_cost))
        self.memory_cost = int(getattr(settings, "AUTH_ARGON2_MEMORY_COST", self.memory_cost))
        self.parallelism = int(getattr(settings, "AUTH_ARGON2_PARALLELISM", self.parallelism))

    def encode(self, password, salt):
        return super().encode(self._pepper(password), salt)

    def verify(self, password, encoded):
        return super().verify(self._pepper(password), encoded)

    def harden_runtime(self, password, encoded):
        return super().harden_runtime(self._pepper(password), encoded)


class PepperedPBKDF2PasswordHasher(_PepperedHasherMixin, PBKDF2PasswordHasher):
    algorithm = "peppered_pbkdf2_sha256"

    def __init__(self):
        super().__init__()
        self.iterations = int(getattr(settings, "AUTH_PBKDF2_ITERATIONS", self.iterations))

    def encode(self, password, salt, iterations=None):
        return super().encode(self._pepper(password), salt, iterations)
