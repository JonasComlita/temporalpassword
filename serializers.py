# apps/authentication/serializers.py
import logging

from django.utils import timezone
from datetime import timedelta
from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from rest_framework.exceptions import ValidationError, AuthenticationFailed
from django.contrib.auth.password_validation import validate_password as django_validate_password
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .services import PasswordResetService, AccountUnlockService # Removed TwoFactorService, SecurityService
from django.core.exceptions import ValidationError as DjangoValidationError
from apps.users.models import TemporalPassword
from django.contrib.auth.hashers import make_password
from django.db.models import Q
from .temporal import encode_temporal_combined_secret

User = get_user_model()
logger = logging.getLogger(__name__)


MAX_FAILED_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCK_MINUTES = 15


def _record_failed_login_attempt(user):
    user.failed_login_attempts += 1
    update_fields = ['failed_login_attempts']
    if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
        user.locked_until = timezone.now() + timedelta(minutes=ACCOUNT_LOCK_MINUTES)
        update_fields.append('locked_until')
    user.save(update_fields=update_fields)


def _enforce_login_policy(user):
    if not user.is_active:
        raise AuthenticationFailed('User account is disabled.', code='authorization')

    if user.is_locked and user.locked_until and user.locked_until > timezone.now():
        raise AuthenticationFailed('Account locked due to too many failed login attempts.', code='account_locked')

    if user.failed_login_attempts > 0:
        user.failed_login_attempts = 0
        user.locked_until = None
        user.save(update_fields=['failed_login_attempts', 'locked_until'])

    if not user.is_verified:
        raise AuthenticationFailed(
            'Email address not verified. Please check your email.',
            code='email_not_verified'
        )


class AccountStatusSerializer(serializers.Serializer):
    """Serializer for returning account lock status."""
    is_locked = serializers.BooleanField(default=False)
    locked_until = serializers.DateTimeField(allow_null=True, required=False)
    remaining_attempts = serializers.IntegerField(default=5) # Default to max attempts

class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    password = serializers.CharField(write_only=True, required=True)
    password_confirm = serializers.CharField(write_only=True, required=True)
    email = serializers.EmailField(required=True)
    username = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password_confirm', 'first_name', 'last_name')
        extra_kwargs = {
            'first_name': {'required': False},
            'last_name': {'required': False},
        }

    def validate_email(self, value):
        """Check if the email is already in use."""
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate_username(self, value):
        """Check if the username is already in use."""
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("A user with this username already exists.")
        # Add any other username validation rules here (e.g., allowed characters)
        return value

    def validate(self, attrs):
        """Check if passwords match."""
        if attrs.get('password') != attrs.get('password_confirm'):
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})
        
        try:
            django_validate_password(attrs.get('password'))
        except DjangoValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)})
            
        return attrs

    def create(self, validated_data):
        """Create and return a new user."""
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            is_active=True, # User is active but needs email verification
            is_verified=False
        )
        # Note: Email verification sending logic will be in the view/service
        return user


class LoginSerializer(serializers.Serializer):
    """Serializer for user login."""
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True) # write_only hides it from response

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')
        request = self.context.get('request')

        if not username or not password:
            raise serializers.ValidationError("Must include 'username' and 'password'.", code='authorization')

        user = authenticate(request=request, username=username, password=password)

        if not user:
            user_obj = None
            try:
                user_obj = User.objects.get(Q(username__iexact=username) | Q(email__iexact=username))
            except User.DoesNotExist:
                user_obj = None

            if user_obj:
                _record_failed_login_attempt(user_obj)

                if user_obj.is_locked:
                    raise AuthenticationFailed('Account locked due to too many failed login attempts.', code='account_locked')

            raise AuthenticationFailed('Invalid credentials, please try again.', code='invalid_credentials')

        _enforce_login_policy(user)

        # Check if 2FA is needed (can be done here or in the view)
        if user.two_factor_enabled:
            attrs['requires_two_factor'] = True

        attrs['user'] = user
        return attrs


class LogoutSerializer(serializers.Serializer):
    """Serializer for user logout (requires refresh token)."""
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': ('Token is invalid or expired')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')
        except AttributeError:
            # Handle cases where token blacklisting is not enabled
            pass

class RequestPasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        # Validation remains the same
        if not User.objects.filter(email__iexact=value, is_active=True).exists():
            pass
        return value

    def save(self):
        email = self.validated_data['email']
        try:
            user = User.objects.get(email__iexact=email, is_active=True)
            # Call service directly - Service handles logging and queuing email task
            PasswordResetService.send_password_reset_email(user)
        except User.DoesNotExist:
            pass # Silently ignore
        except Exception as e:
            logger.exception("Error processing password reset request.")
            pass # Log error but return success to user
        return {"message": "If an account with this email exists, a password reset link has been sent."}


class ConfirmPasswordResetSerializer(serializers.Serializer):
    token = serializers.UUIDField(required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[django_validate_password])
    password_confirm = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})
        return attrs

    def save(self):
        token_id = str(self.validated_data['token'])
        password = self.validated_data['password']
        # Service verifies token, updates password, and logs confirm event
        success = PasswordResetService.confirm_reset_token(token_id, password)
        if not success:
            raise ValidationError("Invalid or expired password reset token.", code='invalid_token')
        # Return success indicator
        return True
    
class PasswordReauthSerializer(serializers.Serializer):
    """Requires current password for re-authentication."""
    current_password = serializers.CharField(write_only=True, required=True)

    def validate_current_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Incorrect current password.")
        return value
    
class TwoFactorCodeSerializer(serializers.Serializer):
    """Serializer for verifying a 2FA code (TOTP or Backup)."""
    code = serializers.CharField(required=True, max_length=10) # 6 for TOTP, maybe 8-10 for backup code
    backup_code = serializers.BooleanField(default=False) # Flag to indicate if it's a backup code

class TwoFactorEnableSerializer(serializers.Serializer):
    # Corrected min_length usage
    code = serializers.CharField(required=True, min_length=6, max_length=6) # Use min_length and max_length

    def validate_code(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Code must be a 6-digit number.")
        return value
    
class TwoFactorDisableSerializer(PasswordReauthSerializer): # Inherit password check
    """Serializer for disabling 2FA, requires current password."""
    # Password field inherited
    pass # No extra fields needed, validation happens in view/service
    
class RequestUnlockCodeSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)

    def validate_username(self, value):
        try:
            user = User.objects.get(username__iexact=value) # Check if user exists by username
            if not user.is_locked:
                 # Don't reveal status, just don't send email
                 # raise serializers.ValidationError("Account is not locked.")
                 pass
        except User.DoesNotExist:
             # Don't reveal user existence
             pass
        return value

    def save(self):
        username = self.validated_data['username']
        try:
            user = User.objects.get(username__iexact=username)
            if user.is_locked:
                AccountUnlockService.send_unlock_email(user)
        except User.DoesNotExist:
             pass # Do nothing if user doesn't exist
        except Exception as e:
             logger.exception("Error processing unlock code request.")
             pass # Log error but return success to user
        return {"message": "If your account is locked and exists, an unlock code has been sent to your email."}


class UnlockAccountSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    unlock_code = serializers.CharField(required=True) # Expecting the UUID string

    def validate(self, attrs):
        username = attrs['username']
        code = attrs['unlock_code']
        try:
             user = User.objects.get(username__iexact=username)
        except User.DoesNotExist:
             raise serializers.ValidationError("Invalid unlock request.", code='invalid')

        if not user.is_locked:
            raise serializers.ValidationError("Account is not locked.", code='not_locked')

        if not AccountUnlockService.verify_unlock_token(user, code):
             # TODO: Optionally add attempt tracking for unlock codes
            raise serializers.ValidationError("Invalid or expired unlock code.", code='invalid_code')

        attrs['user'] = user # Pass user to view if needed
        return attrs

class TemporalPasswordRegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for registering a user with a temporal password.
    """
    password_groups = serializers.ListField(
        child=serializers.CharField(allow_blank=False),
        write_only=True,
        min_length=8,
        max_length=64
    )
    time_intervals = serializers.ListField(
        child=serializers.IntegerField(min_value=0, max_value=99),
        write_only=True,
        min_length=8,
        max_length=64
    )

    class Meta:
        model = User
        fields = ('username', 'email', 'password_groups', 'time_intervals')
        extra_kwargs = {
            'email': {'required': True}
        }

    def validate(self, attrs):
        if len(attrs['password_groups']) != len(attrs['time_intervals']):
            raise serializers.ValidationError("The number of password groups must match the number of time intervals.")
        return attrs

    def create(self, validated_data):
        # The password for the User model will be unusable, as authentication
        # will be handled by the TemporalPasswordBackend.
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=None  # Set a placeholder or unusable password
        )
        user.set_unusable_password()
        user.save()

        combined_secret = encode_temporal_combined_secret(
            validated_data['password_groups'],
            validated_data['time_intervals'],
        )
        combined_secret_hash = make_password(combined_secret)
        
        TemporalPassword.objects.create(
            user=user,
            combined_secret_hash=combined_secret_hash,
        )
        return user

class TemporalPasswordGroupSerializer(serializers.Serializer):
    text = serializers.CharField(allow_blank=False, trim_whitespace=False)
    time = serializers.IntegerField(min_value=0, max_value=99)


class TemporalPasswordLoginSerializer(serializers.Serializer):
    """
    Serializer for logging in a user with a temporal password.
    The actual authentication logic is in the backend.
    """
    username = serializers.CharField()
    password_groups = TemporalPasswordGroupSerializer(
        many=True,
        write_only=True,
        min_length=8,
        max_length=64,
    )

    def validate(self, attrs):
        request = self.context.get('request')
        username = attrs.get('username')
        password_groups = attrs.get('password_groups')

        user = authenticate(request=request, username=username, password_groups=password_groups)

        if not user:
            user_obj = User.objects.filter(username__iexact=username).first()
            if user_obj:
                _record_failed_login_attempt(user_obj)
                if user_obj.is_locked:
                    raise AuthenticationFailed('Account locked due to too many failed login attempts.', code='account_locked')

            raise AuthenticationFailed('Invalid credentials, please try again.', code='invalid_credentials')

        _enforce_login_policy(user)

        if user.two_factor_enabled:
            attrs['requires_two_factor'] = True

        attrs['user'] = user
        return attrs
