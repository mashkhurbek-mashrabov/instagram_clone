import re

from rest_framework.exceptions import ValidationError


def is_email(email):
    return re.fullmatch(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b', email)


def is_phone_number(phone_number):
    return re.fullmatch(r'\+998\d{9}$', phone_number)


def is_email_or_phone_number(text):
    if is_email(text):
        return 'email'
    elif is_phone_number(text):
        return 'phone_number'
    raise ValidationError({'email_phone_number': f'Invalid phone number or email: {text}'})
