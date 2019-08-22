from rest_framework import serializers
from .models import Account


def user_validation(username):
    if username == '':
        raise serializers.ValidationError('This field is requiredsssss')
    else:
        try:
            user = Account.objects.get(username=username)
            raise serializers.ValidationError('Username was taken')
        except:
            return username
