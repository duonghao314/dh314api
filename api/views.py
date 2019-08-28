import json
import uuid

import jwt
from datetime import timedelta, datetime, timezone

from django.shortcuts import render
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.contrib.auth.hashers import make_password
from django.conf import settings

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated

from rest_framework.decorators import \
    (authentication_classes,
     permission_classes)
from oauth2_provider.models import AccessToken, RefreshToken
from oauthlib import common

from . import serializers
from .models import Account, Profile, BlackList, AccessTokenModel
# from .permissions import UpdateOwnAccount
from .tokens import email_activation_token
from controller.functions import check_blacklist_token


@authentication_classes([])
@permission_classes([])
class AuthView(APIView):
    def post(self, request, ):
        serializer = serializers.AuthSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.data.get('username')
            password = serializer.data.get('password')

            try:
                acc = Account.objects.get(username=username)
            except:
                return Response({"message": "Authentication failed"},
                                status=status.HTTP_400_BAD_REQUEST)
            if acc.check_password(raw_password=password):

                """Return accesstoken"""
                payload = {
                    'uuid': str(acc.uuid),
                    'username': acc.username,
                    'time': str(datetime.now(timezone.utc)),
                }
                access_token = jwt.encode(payload, settings.SECRET_KEY).decode(
                    'utf-8')
                try:
                    to_black_list = AccessTokenModel.objects.get(user=acc)
                    token_black_list = BlackList()
                    token_black_list.token = to_black_list.value
                    to_black_list.delete()
                    token_black_list.save()
                except:
                    pass

                to_access_token = AccessTokenModel()
                to_access_token.user = acc
                to_access_token.value = str(access_token)
                to_access_token.save()

                expires = datetime.now() + timedelta(days=3)
                refresh_token = AccessToken(
                    user=acc,
                    expires=expires,
                    token=common.generate_token(),
                )

                refresh_token.save()
                payload2 = {
                    'token': str(refresh_token)
                }
                refresh_token_str = jwt.encode(payload2,
                                               settings.SECRET_KEY).decode(
                    'utf-8')
                decode_token = jwt.decode(refresh_token_str,
                                          settings.SECRET_KEY)
                tokens = {
                    'access token': access_token,
                    # 'refresh token': str(refresh_token),
                    'refresh token': refresh_token_str,
                    # 'decode': decode_token['token']
                }
                # at = AccessToken.objects.all().order_by('-id')[0]
                # if datetime.now(timezone.utc) < at.expires:
                #     print('not ex')
                # else:
                #     print('ex')

                return Response(tokens,
                                status=status.HTTP_201_CREATED)
            else:
                """Return HTTP_400"""
                return Response({"message": "Authentication failed"},
                                status=status.HTTP_400_BAD_REQUEST)
    # except:
    #     return Response({"message": "Authentication failed"},
    #                     status=status.HTTP_400_BAD_REQUEST)


class AuthRefreshView(APIView):
    serializer_class = serializers.RefreshTokenSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        if check_blacklist_token(request):
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        serializer = serializers.RefreshTokenSerializer(data=request.data)

        if serializer.is_valid():
            token = serializer.data.get('refresh_token')
            decoded_token = jwt.decode(token, settings.SECRET_KEY)

            try:
                valid_token = AccessToken.objects.get(
                    token=decoded_token['token'])
                if datetime.now(timezone.utc) < valid_token.expires:
                    username = valid_token.user.username
                    acc = Account.objects.get(username=username)
                    payload = {
                        'uuid': str(acc.uuid),
                        'username': acc.username,
                        'time': str(datetime.now(timezone.utc)),
                    }
                    access_token = jwt.encode(payload,
                                              settings.SECRET_KEY).decode(
                        'utf-8')
                    return Response({'access token': access_token},
                                    status=status.HTTP_200_OK)
                else:
                    return Response(status=status.HTTP_400_BAD_REQUEST)
            except:
                return Response({'message': 'Refresh token not found'},
                                status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class AuthrevokeView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        if check_blacklist_token(request):
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        serializer = serializers.RevokeTokenSerializer(data=request.data)
        if serializer.is_valid():
            refresh_token = serializer.data.get('refresh_token')
            try:
                decoded_token = jwt.decode(refresh_token, settings.SECRET_KEY)[
                    'token']
            except:
                return Response(
                    {"message": "This is not refresh token"},
                    status=status.HTTP_400_BAD_REQUEST)
            print(decoded_token)
            try:
                to_delete_token = AccessToken.objects.get(
                    token=str(decoded_token))
                if to_delete_token.user.username != str(request.user.username):
                    return Response({
                        "message": "Access token and refresh token do not "
                                   "match",

                    },
                        status=status.HTTP_400_BAD_REQUEST)
                print(to_delete_token.user)
                to_delete_token.delete()
            except:
                return Response({'message': 'Refresh token was not found'},
                                status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_200_OK)


class AuthVerifyView(APIView):
    serializer_class = serializers.AuthSerializer
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        if check_blacklist_token(request):
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        return Response({'verify': True}, status=status.HTTP_200_OK)

    # def post(self, request, ):
    #     serializer = serializers.AuthSerializer(data=request.data)
    #     if serializer.is_valid():
    #         username = serializer.data.get('username')
    #         password = serializer.data.get('password')
    #
    #         try:
    #             user = Account.objects.get(username=username)
    #             if user.check_password(raw_password=password):
    #                 """Return accesstoken"""
    #                 print('true')
    #             else:
    #                 """Return HTTP_400"""
    #                 return Response({"message": "Authentication failed"},
    #                                 status=status.HTTP_400_BAD_REQUEST)
    #         except:
    #             return Response({"message": "Authentication failed"},
    #                             status=status.HTTP_400_BAD_REQUEST)
    #     return Response({'username': username, 'password': password})


class AuthMEView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, formar=None):
        if check_blacklist_token(request):
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        acc = Account.objects.get(username=request.user.username)
        prof = ''
        print(acc.uuid)
        try:
            prof = Profile.objects.get(uuid=acc.uuid).to_dic()

        except:
            prof = 'null'
        print(prof)
        user_infor = {
            'id': str(acc.uuid),
            'username': acc.username,
            'email': acc.email,
            'timezone': acc.timezone,
            'profile': prof
        }
        return Response(user_infor, content_type='application/json',
                        status=status.HTTP_200_OK)


@authentication_classes([])
@permission_classes([])
class AccountCreateView(APIView):
    serializer_class = serializers.AccountSerializer

    def post(self, request):
        serializer = serializers.AccountSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.data.get('username')
            password = serializer.data.get('password')
            email = serializer.data.get('email')
            acc = Account()
            acc.username = username
            acc.password = make_password(password)
            if email != '':
                acc.email = email
            acc.save()
            return Response(status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)


class DeleteView(APIView):
    permission_classes = (IsAuthenticated,)

    def delete(self, request):
        if check_blacklist_token(request):
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        acc = Account.objects.get(username=request.user.username)
        try:
            prof = Profile.objects.get(uuid=acc.uuid)
            prof.delete()
        except:
            pass
        acc.delete()
        return Response(status=status.HTTP_200_OK)


class UpdateEmailView(APIView):
    permission_classes = (IsAuthenticated,)

    def patch(self, request):
        if check_blacklist_token(request):
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        serializer = serializers.UpdateEmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.data.get('email')
            acc = Account.objects.get(username=request.user.username)
            acc.email = email
            acc.save()
            return Response(status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    permission_classes = (IsAuthenticated,)

    def patch(self, request):
        serializer = serializers.ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            # current_password = serializer.data.get('current_password')
            password = serializer.data.get('password')
            # confirmed_password = serializer.data.get('confirmed_password')
            acc = Account.objects.get(username=request.user.username)

            acc.password = make_password(password)
            acc.save()
            try:
                to_black_list = AccessTokenModel.objects.get(user=acc)
                token_black_list = BlackList()
                token_black_list.token = to_black_list.value
                to_black_list.delete()
                token_black_list.save()
            except:
                pass

            return Response(status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)


class UpdateProfileView(APIView):
    permission_classes = (IsAuthenticated,)

    def patch(self, request):
        if check_blacklist_token(request):
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        serializer = serializers.UpdateProfileSerializer(data=request.data)
        if serializer.is_valid():
            fullname = serializer.data.get('fullname')
            address = serializer.data.get('address')
            country = serializer.data.get('country')
            phone = serializer.data.get('phone')
            date_of_birth = serializer.data.get('date_of_birth')

            acc = Account.objects.get(username=request.user.username)
            profiles = Profile.objects.all().count()

            # if str(acc.uuid) in [profile.uuid for profile in profiles]:
            if Profile.objects.filter(uuid=str(acc.uuid)).exists():
                prof = profiles.get(uuid=acc.uuid)
                if fullname != '':
                    prof.fullname = fullname
                if address != '':
                    prof.address = address
                if country != '':
                    prof.country = country
                if phone != '':
                    prof.phone = phone
                if date_of_birth != '':
                    print(date_of_birth)
                    prof.date_of_birth = date_of_birth
                prof.save()
                return Response(status=status.HTTP_200_OK)
            else:
                prof = Profile(id=(profiles + 1), uuid=acc.uuid,
                               fullname=fullname, address=address,
                               country=country, phone=phone,
                               date_of_birth=date_of_birth)
                prof.save()
        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)


class SendEmailConfirmView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        if check_blacklist_token(request):
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        acc = Account.objects.get(username=request.user.username)
        to_email = acc.email
        current_site = get_current_site(request)
        message = render_to_string('email_active.html', {
            'user': acc,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(acc.uuid)),
            'token': email_activation_token.make_token(acc),
        })
        mail_subject = 'Activate your blog account.'
        to_email = to_email
        email = EmailMessage(mail_subject, message, to=[to_email])
        email.send()
        return Response(status=status.HTTP_200_OK)


def ConfirmEmailView(request, uidb64, token):
    try:
        uuid = force_text(urlsafe_base64_decode(uidb64))
        acc = Account.objects.get(uuid=uuid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        acc = None
    if acc is not None and email_activation_token.check_token(acc, token):
        acc.email_confirmed = True
        acc.save()

        # return redirect('home')
        return HttpResponse(status=status.HTTP_200_OK)
    else:
        return HttpResponse(status=status.HTTP_400_BAD_REQUEST)
