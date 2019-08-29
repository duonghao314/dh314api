from django.conf.urls import url
from django.conf.urls import include
from django.urls import path
# from rest_framework_simplejwt import views as jwt_views
from rest_framework_jwt.views import obtain_jwt_token, refresh_jwt_token, \
    verify_jwt_token
import oauth2_provider.views as oauth2_views
from rest_framework.routers import DefaultRouter

from . import views

urlpatterns = [

    # path('auth/', views.AuthView.as_view()),
    path('auth/', views.AuthView.as_view()),
    path('auth/verify/', views.AuthVerifyView.as_view()),
    path('auth/me/', views.AuthMEView.as_view()),
    path('accounts/', views.AccountCreateView.as_view()),
    path('account/', views.DeleteView.as_view()),
    path('account/email', views.UpdateEmailView.as_view()),
    path('profile/', views.UpdateProfileView.as_view()),
    path('auth/refresh/', views.AuthRefreshView.as_view()),
    path('account/password/', views.ChangePasswordView.as_view()),
    path('auth/revoke/', views.AuthrevokeView.as_view()),
    path('account/send-confirmed-email/',
         views.SendEmailConfirmView.as_view()),
    path('account/confirm-email/<str:uidb64>/<str:token>/',
         views.ConfirmEmailView)

    # path('auth/', jwt_views.TokenObtainPairView.as_view(), name ='auth'),
    # url(r'^jwt/api-token-auth/', jwt_views.TokenRefreshView.as_view(), name='obtain_jwt_token'),
]
