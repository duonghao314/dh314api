import uuid
import pytz
import datetime

from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.models import BaseUserManager


# Create your models here.

class AccountManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        username = username
        email = self.normalize_email(email)
        timezone = 'Asia/Ho_Chi_Minh'
        user = self.model(username=username, email=email)
        user.timezone = timezone
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, username, email, password):
        timezone = 'Asia/Ho_Chi_Minh'
        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.save(using=self._db)

        return user


class Account(AbstractBaseUser, PermissionsMixin):
    TIMEZONES = tuple(zip(pytz.all_timezones, pytz.all_timezones))

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4,
                            editable=False)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(max_length=255, blank=True)
    email_confirmed = models.BooleanField(default=False)
    timezone = models.CharField(max_length=52, choices=TIMEZONES,
                                default='', blank=True)
    is_staff = models.BooleanField(default=True)
    objects = AccountManager()
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username


class Profile(models.Model):
    id = models.IntegerField(primary_key=True, unique=True, auto_created=True)
    uuid = models.TextField(unique=True)
    fullname = models.CharField(max_length=50, blank=True, null=True)
    address = models.CharField(max_length=100, blank=True, null=True)
    country = models.CharField(max_length=32, blank=True, null=True)
    phone = models.CharField(max_length=15, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True,
                                     default=datetime.datetime(2000, 1, 1))

    @classmethod
    def create(cls, id, uuid, fullname='', address='', country='', phone='',
               dob=''):
        profile = cls(id=id, uuid=uuid, fullname=fullname, address=address,
                      country=country, phone=phone, date_of_birth=dob)
        return profile

    def __str__(self):
        return self.uuid

    def to_dic(self):
        dict = {
            'fullname': self.fullname,
            'date_of_birth': self.date_of_birth,
            'address': self.address,
            'country': self.country,
            'phone': self.phone
        }
        return dict


class AccessTokenModel(models.Model):
    user = models.ForeignKey(Account, on_delete=models.CASCADE)
    value = models.TextField()


class BlackList(models.Model):
    token = models.TextField()
