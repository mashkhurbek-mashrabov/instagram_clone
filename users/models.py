import random
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.db import models

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

    def create_verify_code(self, verify_type):
        code = random.randint(1000, 9999)
        UserConfirmation.objects.create(user=self, code=code, verification_type=verify_type)
        return code


class UserConfirmation(BaseModel):
    code = models.CharField(max_length=4)
    user = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='verify_codes')
    verification_type = models.SmallIntegerField(choices=VerificationTypeChoices.choices,
                                                 default=VerificationTypeChoices.EMAIL)
    expiration_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)

    def __str__(self):
        return self.user.__str__()

    def save(self, *args, **kwargs):
        if not self.pk:
            expiration_minute = {
                VerificationTypeChoices.EMAIL: settings.CONFIRMATION_EXPIRATION_MINUTE_VIA_EMAIL,
                VerificationTypeChoices.PHONE_NUMBER: settings.CONFIRMATION_EXPIRATION_MINUTE_VIA_PHONE,
            }
            self.expiration_time = datetime.now() + timedelta(minutes=expiration_minute.get(self.verification_type))
        return super(UserConfirmation, self).save(*args, **kwargs)
