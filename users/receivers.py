from datetime import datetime, timedelta

from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

from users.constants import VerificationTypeChoices
from users.models import UserConfirmation


@receiver(post_save, sender=UserConfirmation)
def create_user_confirmation(sender, instance, created, **kwargs):
    if created:
        expiration_minute = {
            VerificationTypeChoices.EMAIL: settings.CONFIRMATION_EXPIRATION_MINUTE_VIA_EMAIL,
            VerificationTypeChoices.PHONE_NUMBER: settings.CONFIRMATION_EXPIRATION_MINUTE_VIA_PHONE,
        }
        instance.expiration_time = datetime.now(tz=timezone.utc) + timedelta(
            minutes=expiration_minute.get(instance.verification_type))
        instance.save()
