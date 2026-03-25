from django.contrib.auth.backends import ModelBackend, BaseBackend
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.contrib.auth.hashers import check_password
from apps.users.models import TemporalPassword
from .temporal import (
    encode_temporal_combined_secret,
)

class EmailOrUsernameModelBackend(ModelBackend):
    """
    This is a ModelBacked that allows authentication with either a username or an email address.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            # Try to fetch the user by searching the username or email field.
            user = UserModel.objects.get(Q(username__iexact=username) | Q(email__iexact=username))
            if user.check_password(password):
                return user
        except UserModel.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between a user existing and not existing.
            UserModel().set_password(password)
        return None

class TemporalPasswordBackend(BaseBackend):
    def authenticate(self, request, username=None, password_groups=None, **kwargs):
        # If this backend is being used for a non-temporal login, step aside.
        if password_groups is None:
            return None

        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(username__iexact=username)
            temporal_password = TemporalPassword.objects.get(user=user)

            # 1. Verify the primary (text) component
            if not all(isinstance(group, dict) for group in password_groups):
                return None

            submitted_text_groups = [group['text'] for group in password_groups]
            submitted_times = [group['time'] for group in password_groups]

            if not all(isinstance(group, str) and group for group in submitted_text_groups):
                return None
            if not all(isinstance(interval, int) and 0 <= interval <= 99 for interval in submitted_times):
                return None

            combined_secret = encode_temporal_combined_secret(submitted_text_groups, submitted_times)
            if not check_password(combined_secret, temporal_password.combined_secret_hash):
                return None
            
            return user # Authentication successful: BOTH components match
        except (UserModel.DoesNotExist, TemporalPassword.DoesNotExist, KeyError, TypeError, ValueError):
            return None

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            return UserModel.objects.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
