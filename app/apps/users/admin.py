from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from users.models import User, UserConfirmation


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'phone_number', 'is_active', 'is_staff', 'is_superuser')
    list_filter = ('auth_type', 'created_at', 'is_active', 'is_staff', 'is_superuser')
    search_fields = ('username', 'email', 'phone_number')


@admin.register(UserConfirmation)
class UserConfirmationAdmin(admin.ModelAdmin):
    list_display = ('user', 'code', 'expiration_time', 'is_confirmed')
    list_filter = ('expiration_time', 'is_confirmed')
    search_fields = ('user', 'code')
