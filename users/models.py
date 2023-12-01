import random
import uuid
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.db import models
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from common.models import BaseModel
from users.constants import UserRoles, AuthTypeChoices, AuthStatusChoices, VerificationTypeChoices


class User(AbstractUser, BaseModel):
    user_role = models.SmallIntegerField(choices=UserRoles.choices, default=UserRoles.USER)
    auth_type = models.SmallIntegerField(choices=AuthTypeChoices.choices, default=AuthTypeChoices.EMAIL)
    auth_status = models.SmallIntegerField(choices=AuthStatusChoices.choices, default=AuthStatusChoices.NEW)
    email = models.EmailField(unique=True, null=True, blank=True)
    phone_number = models.CharField(max_length=13, null=True, blank=True, unique=True)
    photo = models.ImageField(null=True, upload_to="users/photos", blank=True,
                              validators=[FileExtensionValidator(allowed_extensions=['png', 'jpg', 'jpeg'])])

    def __str__(self):
        return self.username

    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'

    @property
    def short_id(self):
        return str(self.id).split('-')[0]

    def create_verify_code(self, verify_type):
        code = random.randint(1000, 9999)
        UserConfirmation.objects.create(user=self, code=code, verification_type=verify_type)
        return code

    def check_username(self):
        if not self.username:
            temp_username = f"temp_{str(uuid.uuid4()).split('-')[0]}"
            while User.objects.filter(username=temp_username).exists():
                temp_username = f"{temp_username}{random.randint(0, 9)}"
            self.username = temp_username

    def check_email(self):
        if self.email:
            self.email = self.email.lower()

    def check_pass(self):
        if not self.password:
            self.password = f"temp_password_{self.short_id}"

    def hashing_password(self):
        if not self.password.startswith('pbkdf2_sha256$'):
            self.set_password(self.password)

    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        }

    def clean(self):
        self.check_username()
        self.check_email()
        self.check_pass()
        self.hashing_password()

    def save(self, *args, **kwargs):
        if not self.pk or not self.username:
            self.clean()
        super(User, self).save(*args, **kwargs)


class UserConfirmation(BaseModel):
    code = models.CharField(max_length=4)
    user = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='verify_codes')
    verification_type = models.SmallIntegerField(choices=VerificationTypeChoices.choices,
                                                 default=VerificationTypeChoices.EMAIL)
    expiration_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)

    def __str__(self):
        return self.user.__str__()
