from datetime import datetime

from django.shortcuts import render
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from users.constants import AuthStatusChoices
from users.models import User, UserConfirmation
from users.serializers import SignUpSerializer


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
        return Response({'message': 'Code verified'}, status=status.HTTP_200_OK)

    @staticmethod
    def code_is_valid(user, code):
        now = datetime.now(tz=timezone.utc)
        try:
            return UserConfirmation.objects.get(user=user, code=code, expiration_time__gte=now, is_confirmed=False)
        except UserConfirmation.DoesNotExist:
            return None
