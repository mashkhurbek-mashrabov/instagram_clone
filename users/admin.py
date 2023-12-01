from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from users.models import User


@admin.register(User)
class UserAdmin(UserAdmin):
    list_display = ('username', 'email', 'phone_number', 'is_active', 'is_staff', 'is_superuser')
    list_filter = ('auth_type', 'created_at', 'is_active', 'is_staff', 'is_superuser')
    search_fields = ('username', 'email', 'phone_number')
