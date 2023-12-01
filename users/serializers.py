from rest_framework import serializers

from common.utils import is_email_or_phone_number
from .constants import AuthTypeChoices
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
            pass
        elif user.auth_type == AuthTypeChoices.PHONE_NUMBER:
            pass
        user.save()

    def validate(self, data):
        super(SignUpSerializer, self).validate(data)
        data = self.auth_validate(data)
        auth_type = is_email_or_phone_number(data.get('email_phone_number'))
        data.update({auth_type: data.get('email_phone_number')})
        del data['email_phone_number']
        data.update({'auth_type': AuthTypeChoices.get_type(auth_type)})
        return data

    @staticmethod
    def auth_validate(data):
        print(data)
        data['email_phone_number'] = data.get('email_phone_number').lower()
        return data
