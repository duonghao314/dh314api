from django.contrib import admin

from .models import Account, Profile, BlackList, AccessTokenModel
# Register your models here.

class AccountAdmin(admin.ModelAdmin):
    list_display = ['uuid', 'username', 'password', 'email', 'email_confirmed', 'timezone']

admin.site.register(Account, AccountAdmin)
admin.site.register(Profile)
admin.site.register(AccessTokenModel)
admin.site.register(BlackList)