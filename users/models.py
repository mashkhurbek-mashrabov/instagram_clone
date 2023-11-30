from django.contrib.auth.models import AbstractUser
from django.db import models

from common.models import BaseModel
from users.constants import UserRoles, AuthTypeChoices, AuthStatusChoices


class User(AbstractUser, BaseModel):
    user_role = models.SmallIntegerField(choices=UserRoles.choices, default=UserRoles.USER)
    auth_type = models.SmallIntegerField(choices=AuthTypeChoices.choices, default=AuthTypeChoices.EMAIL)
    auth_status = models.SmallIntegerField(choices=AuthStatusChoices.choices, default=AuthStatusChoices.NEW)
    email = models.EmailField(unique=True, null=True, blank=True)
    phone_number = models.CharField(max_length=13, null=True, blank=True, unique=True)
    photo = models.ImageField(null=True, upload_to="users/photos", blank=True)

    def __str__(self):
        return self.username
