from primate.admin import UserAdminBase
from django.contrib import admin
from django.contrib.auth.models import User


class UserAdmin(UserAdminBase):
    pass


admin.site.register(User, UserAdmin)