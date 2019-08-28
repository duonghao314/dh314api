from controller.functions import check_blacklist_token

from rest_framework.response import Response
from rest_framework import status

def token_not_in_blacklist(func):
    def wrapper(self, request, *args, **kwargs):
        if check_blacklist_token(request):
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        else:
            return func(self,request, *args, **kwargs)
    return wrapper