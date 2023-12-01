import re
import threading

from django.core.mail import EmailMessage
from django.template.loader import render_to_string
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


class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


class Email:
    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            to=[data['to_email']]
        )

        if data.get('content_type') == 'email':
            email.content_subtype = 'html'
        EmailThread(email=email).start()


def send_confirmation_email(email, code):
    html_content = render_to_string('email/authentication/activate_account.html', {'code': code})
    Email.send_email(
        {
            'subject': 'Activate your account',
            'to_email': email,
            'content_type': 'html',
            'body': html_content
        }
    )


def send_sms(phone_number, code):
    print(f"Code has been sent to {phone_number}\nCode: {code}")
