import datetime

from django.core.validators import validate_email

from rest_framework import serializers
from iso3166 import countries
import phonenumbers

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
            if Account.objects.filter(username=value).exists():
                raise serializers.ValidationError('Username was taken')
        return value

    def validate_password(self, value):
        if value == '':
            raise serializers.ValidationError('This field is required')
        return value

    def validate_email(self, value):
        if value == '' or value == None:
            value = ''
            return value
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

    def validate(self, attrs):
        # Validate Country
        if attrs['country'] == '' or attrs['country'] == None:
            attrs['country'] = ''
        elif attrs['country'] not in countries:
            raise serializers.ValidationError('Invalid country')

        # Validate phone number
        country_code = None
        if attrs['country'] != '':
            country_code = countries[attrs['country']][1]
        try:
            phone_number = phonenumbers.parse(attrs['phone'], country_code)
            if not phonenumbers.is_valid_number(phone_number):
                raise serializers.ValidationError('Invalid phone number')
        except:
            raise serializers.ValidationError('Invalid phone number')

        # Validate date of birth
        if attrs['date_of_birth'] == '' or attrs['date_of_birth'] == None:
            attrs['date_of_birth'] = ''
        else:
            try:
                datetime.datetime.strftime(attrs['date_of_birth'], '%Y-%m-%d')
            except:
                raise serializers.ValidationError('Invalid date')

        return attrs


class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=500)


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(max_length=32)
    password = serializers.CharField(max_length=32)
    confirmed_password = serializers.CharField(max_length=32)

    def validate(self, attrs):
        username = self.context['request'].user.username
        try:
            acc = Account.objects.get(username=username)
            password = attrs['password']
            if not acc.check_password(raw_password=password):
                raise serializers.ValidationError('Incorrect Password')
        except:
            raise serializers.ValidationError('Incorrect Password')
        if attrs['current_password'] == attrs['password']:
            raise serializers.ValidationError('Current password cant be reuse')
        if attrs['password'] != attrs['confirmed_password']:
            raise serializers.ValidationError('Confirmed password not match')
        return attrs


class RevokeTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=500)
