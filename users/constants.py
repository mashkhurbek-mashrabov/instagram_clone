from django.db.models import IntegerChoices


class UserRoles(IntegerChoices):
    ADMIN = 1, 'Admin'
    MANAGER = 2, 'Manager'
    USER = 3, 'User'


class AuthTypeChoices(IntegerChoices):
    EMAIL = 1, 'Email'
    PHONE_NUMBER = 2, 'Phone Number'


class AuthStatusChoices(IntegerChoices):
    NEW = 1, 'New'
    CODE_VERIFIED = 2, 'Code Verified'
    DONE = 3, 'Done'
    PHOTO_STEP = 4, 'Photo Step'


class VerificationTypeChoices(IntegerChoices):
    EMAIL = 1, 'Email'
    PHONE_NUMBER = 2, 'Phone Number'