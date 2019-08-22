import datetime

from django.core.validators import validate_email

from rest_framework import serializers
from iso3166 import countries

from .models import Account
from . import validations


class AccountSerializer(serializers.ModelSerializer):
    """A serializer for our user profile objects."""

    class Meta:
        model = Account
        fields = ('uuid', 'username', 'email', 'password', 'timezone')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        """Create and return a new user."""

        user = Account(
            username=validated_data['username'],
            email=validated_data['email'],
            timezone=validated_data['timezone'],
        )

        user.set_password(validated_data['password'])
        user.save()

        return user


class AuthSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50)
    password = serializers.CharField(max_length=32)


class AccountSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50, allow_blank=True)
    password = serializers.CharField(max_length=32, allow_blank=True)
    email = serializers.CharField(allow_blank=True, max_length=255)

    def validate_username(self, value):
        if value == '':
            raise serializers.ValidationError('This field is required')
        else:
            users = Account.objects.all()
            if value in [user.username for user in users]:
                raise serializers.ValidationError('Username was taken')
        return value

    def validate_password(self, value):
        if value == '':
            raise serializers.ValidationError('This field is required')
        return value

    def validate_email(self, value):
        try:
            validate_email(value)
        except:
            raise serializers.ValidationError('Email is invalid')
        return value


class UpdateEmailSerializer(serializers.Serializer):
    email = serializers.CharField(allow_blank=True, max_length=255)

    def validate_email(self, value):
        try:
            validate_email(value)
        except:
            raise serializers.ValidationError('Email is invalid')
        return value


class UpdateProfileSerializer(serializers.Serializer):
    fullname = serializers.CharField(max_length=100, allow_blank=True)
    address = serializers.CharField(max_length=200, allow_blank=True)
    country = serializers.CharField(max_length=50, allow_blank=True)
    phone = serializers.CharField(max_length=20, allow_blank=True)
    date_of_birth = serializers.CharField(max_length=10, allow_blank=True)

    def validate_country(self, value):
        if value not in countries:
            raise serializers.ValidationError('Invalid country')
        return value

    def validate_phone(self, value):
        if len(value) <= 15 and len(value) >= 8:
            try:
                phone_int = int(value)
            except:
                raise serializers.ValidationError('Invalid phone number')
        else:
            raise serializers.ValidationError('Invalid phone number')
        return value

    def validate_date_of_birth(self, value):
        if value == '':
            return value
        else:
            try:
                datetime.datetime.strptime(value, '%Y-%m-%d')

            except:
                raise serializers.ValidationError('Invalid date')
            return value


class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=500)


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(max_length=32)
    password = serializers.CharField(max_length=32)
    confirmed_password = serializers.CharField(max_length=32)

    def validate(self, attrs):
        if attrs['current_password'] == attrs['password']:
            raise serializers.ValidationError('Current password cant be reuse')
        if attrs['password'] != attrs['confirmed_password']:
            raise serializers.ValidationError('Confirmed password not match')
        return attrs

class RevokeTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=500)