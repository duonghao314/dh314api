from rest_framework.response import Response
from rest_framework import status

from api.models import BlackList


def check_blacklist_token(request):
    token = str(request.META.get('HTTP_AUTHORIZATION'))

    if token.startswith('Bearer '):
        token = token.replace('Bearer ', '')

        # if token in [bl_token.token for bl_token in BlackList.objects.all()]:
        if BlackList.objects.filter(token=token).exists():
            return True
    return False
