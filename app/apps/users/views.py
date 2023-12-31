from datetime import datetime

from django.shortcuts import render
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from common.utils import send_confirmation_email, send_sms, is_email_or_phone_number
from users.constants import AuthStatusChoices, AuthTypeChoices
from users.models import User, UserConfirmation
from users.serializers import SignUpSerializer, SetUserInformationSerializer, ChangeUserSerializer, LoginSerializer, \
    LoginRefreshTokenSerializer, LogoutSerializer, ForgotPasswordSerializer, ResetPasswordSerializer


class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignUpSerializer
    permission_classes = (permissions.AllowAny,)


class VerifyAPIView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        user = request.user
        code = request.data.get('code')

        user_confirmation = self.code_is_valid(user, code)
        if user_confirmation is None:
            raise ValidationError({'message': 'Invalid code'})
        user_confirmation.is_confirmed = True
        user_confirmation.save()
        if user.auth_status == AuthStatusChoices.NEW:
            user.auth_status = AuthStatusChoices.CODE_VERIFIED
            user.save()
        return Response({'message': 'Code verified', **user.token()}, status=status.HTTP_200_OK)

    @staticmethod
    def code_is_valid(user, code):
        now = datetime.now(tz=timezone.utc)
        try:
            return UserConfirmation.objects.get(user=user, code=code, expiration_time__gte=now, is_confirmed=False)
        except UserConfirmation.DoesNotExist:
            return None


class ResendVerifyCodeView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    http_method_names = ['get']

    def get(self, request, *args, **kwargs):
        user = request.user

        if self.check_exist_code(user):
            return Response({'message': 'Code has already been sent', 'success': False}, status=status.HTTP_200_OK)

        if user.auth_status != AuthStatusChoices.NEW:
            return Response({'message': 'User is already verified', 'success': False},
                            status=status.HTTP_400_BAD_REQUEST)

        code = user.create_verify_code(user.auth_type)
        if user.auth_type == AuthTypeChoices.EMAIL:
            send_confirmation_email(user.email, code)
        elif user.auth_type == AuthTypeChoices.PHONE_NUMBER:
            send_sms(user.phone_number, code)
        return Response({'message': 'Code has been resent', 'success': True}, status=status.HTTP_200_OK)

    @staticmethod
    def check_exist_code(user):
        return UserConfirmation.objects.filter(user=user,
                                               expiration_time__gt=datetime.now(tz=timezone.utc),
                                               is_confirmed=False).exists()


class UpdateUserInformationView(UpdateAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = SetUserInformationSerializer
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        super(UpdateUserInformationView, self).update(request, *args, **kwargs)
        return Response({'message': 'User information has been updated successfully',
                         'success': True},
                        status=status.HTTP_200_OK)

    def partial_update(self, request, *args, **kwargs):
        super(UpdateUserInformationView, self).partial_update(request, *args, **kwargs)
        return Response({'message': 'User information has been updated successfully',
                         'success': True},
                        status=status.HTTP_200_OK)


class ChangeUserPhotoView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    http_method_names = ['patch', 'put']
    serializer_class = ChangeUserSerializer

    def put(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            user = request.user
            serializer.update(instance=user, validated_data=serializer.validated_data)
            return Response({'message': 'User photo has been updated successfully', 'success': True},
                            status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer


class LoginRefreshTokenView(TokenRefreshView):
    serializer_class = LoginRefreshTokenSerializer


class LogoutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'message': 'User logged out successfully', 'success': True}, status=status.HTTP_200_OK)


class ForgotPasswordView(APIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = ForgotPasswordSerializer
    http_method_names = ['post']

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data.get('user')
        auth_type = serializer.validated_data.get('auth_type')
        auth_type = AuthTypeChoices.get_type(auth_type)
        code = user.create_verify_code(auth_type)

        if auth_type == AuthTypeChoices.EMAIL:
            send_confirmation_email(user.email, code)
        elif auth_type == AuthTypeChoices.PHONE_NUMBER:
            send_sms(user.phone_number, code)

        return Response({'message': 'Code has been sent', 'success': True, **user.token()}, status=status.HTTP_200_OK)


class ResetPasswordView(UpdateAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = (permissions.IsAuthenticated,)
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        response = super(ResetPasswordView, self).update(request, *args, **kwargs)
        try:
            user = User.objects.get(id=response.data.get('id'))
        except User.DoesNotExist:
            raise ValidationError({'message': 'User does not exist.', 'success': False}, code=status.HTTP_404_NOT_FOUND)

        return Response({'message': 'Password has been reset successfully', **user.token()}, status=status.HTTP_200_OK)
