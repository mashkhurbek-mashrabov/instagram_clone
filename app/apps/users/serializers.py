import re

from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.core.validators import FileExtensionValidator
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers, status
from rest_framework.exceptions import PermissionDenied
from rest_framework.generics import get_object_or_404
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from common.utils import is_email_or_phone_number, send_confirmation_email, send_sms
from .constants import AuthTypeChoices, AuthStatusChoices
from .models import User, UserConfirmation


class SignUpSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)

    def __init__(self, *args, **kwargs):
        super(SignUpSerializer, self).__init__(*args, **kwargs)
        self.fields['email_phone_number'] = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = (
            'id',
            'auth_type',
            'auth_status',
        )
        extra_kwargs = {
            'auth_type': {'read_only': True, 'required': True},
            'auth_status': {'read_only': True, 'required': True}
        }

    def create(self, validated_data):
        user = super(SignUpSerializer, self).create(validated_data)
        code = user.create_verify_code(user.auth_type)

        if user.auth_type == AuthTypeChoices.EMAIL:
            send_confirmation_email(user.email, code)
        elif user.auth_type == AuthTypeChoices.PHONE_NUMBER:
            send_sms(user.phone_number, code)
        user.save()
        return user

    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        email_phone_number = data.get('email_phone_number').lower()
        auth_type = is_email_or_phone_number(email_phone_number)

        if User.objects.filter(**{auth_type: email_phone_number}).exists():
            raise serializers.ValidationError({'email_phone_number': 'Email or phone number already exists.'})

        data.update({auth_type: email_phone_number})
        del data['email_phone_number']
        data.update({'auth_type': AuthTypeChoices.get_type(auth_type)})
        return data

    @staticmethod
    def auth_validate(data):
        data['email_phone_number'] = data.get('email_phone_number').lower()
        return data

    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.update(**instance.token())
        return data


class SetUserInformationSerializer(serializers.Serializer):
    first_name = serializers.CharField(write_only=True, required=False)
    last_name = serializers.CharField(write_only=True, required=False)
    username = serializers.CharField(write_only=True, required=False)
    password = serializers.CharField(write_only=True, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)

    def validate(self, data):
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError({'confirm_password': 'Passwords does not match.'})

        if password:
            validate_password(password)

        return data

    def validate_username(self, username):
        if not 5 <= len(username) <= 30:
            raise serializers.ValidationError(
                {'message': 'Username length must be between 5 and 30 characters.', 'success': False})

        if not re.match("^[a-zA-Z0-9_.-]+$", username):
            raise serializers.ValidationError({'message': 'Invalid username.', 'success': False})

        if User.objects.filter(username=str(username).lower()).exists():
            raise serializers.ValidationError({'message': 'Username already exists.', 'success': False})

        return username

    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.username = validated_data.get('username', instance.username)
        instance.set_password(validated_data.get('password', instance.password))

        if instance.auth_status == AuthStatusChoices.CODE_VERIFIED:
            instance.auth_status = AuthStatusChoices.DONE

        instance.save()
        return instance


class ChangeUserSerializer(serializers.Serializer):
    photo = serializers.ImageField(
        validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'heic', 'heif'])])

    def update(self, instance, validated_data):
        photo = validated_data.get('photo', instance.photo)
        if photo:
            instance.photo = photo
            instance.auth_status = AuthStatusChoices.PHOTO_STEP
            instance.save()
        return instance


class LoginSerializer(serializers.Serializer):

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.fields['userinput'] = serializers.CharField(required=True)
        self.fields['password'] = serializers.CharField(required=True)

    def validate(self, data):
        user = self.auth_validate(data)

        if user.auth_status not in [AuthStatusChoices.DONE, AuthStatusChoices.PHOTO_STEP]:
            raise PermissionDenied('User is not verified. Please verify your account first')

        data = user.token()
        return data

    def auth_validate(self, data):
        user_input = data.get('userinput').lower()
        try:
            user = User.objects.get(
                Q(username__iexact=user_input) | Q(email__iexact=user_input) | Q(phone_number=user_input))
        except User.DoesNotExist:
            raise serializers.ValidationError({'message': 'User does not exist.', 'success': False},
                                              code=status.HTTP_404_NOT_FOUND)

        user = authenticate(username=user.username, password=data.get('password'))
        if user is None:
            raise serializers.ValidationError({'message': 'Invalid username or password.', 'success': False},
                                              code=status.HTTP_400_BAD_REQUEST)

        if user.auth_status in [AuthStatusChoices.CODE_VERIFIED, AuthStatusChoices.NEW]:
            raise serializers.ValidationError({'message': 'User is not verified.', 'success': False},
                                              code=status.HTTP_400_BAD_REQUEST)

        return user


class LoginRefreshTokenSerializer(TokenRefreshSerializer):

    def validate(self, attrs):
        data = super(LoginRefreshTokenSerializer, self).validate(attrs)
        access_token_instance = AccessToken(data['access'])
        user_id = access_token_instance['user_id']
        user = get_object_or_404(User, id=user_id)
        update_last_login(None, user)
        return data


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': _('Token is invalid or expired')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')
        except Exception as e:
            print('\nException in logging out:', e)


class ForgotPasswordSerializer(serializers.Serializer):
    email_phone_number = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        attrs = super(ForgotPasswordSerializer, self).validate(attrs)
        email_phone_number = attrs.get('email_phone_number').lower()

        auth_type = is_email_or_phone_number(email_phone_number)

        try:
            user = User.objects.get(Q(email=email_phone_number) | Q(phone_number=email_phone_number))
        except User.DoesNotExist:
            raise serializers.ValidationError({'message': 'User does not exist.', 'success': False},
                                              code=status.HTTP_404_NOT_FOUND)
        attrs['user'] = user
        attrs['auth_type'] = auth_type
        return attrs


class ResetPasswordSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = (
            'id',
            'password',
            'confirm_password',
        )

    def validate(self, attrs):
        data = super(ResetPasswordSerializer, self).validate(attrs)

        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({'confirm_password': 'Passwords does not match.'})

        validate_password(data['password'])

        return data

    def update(self, instance, validated_data):
        password = validated_data.pop('password')
        instance.set_password(password)
        return super(ResetPasswordSerializer, self).update(instance, validated_data)
