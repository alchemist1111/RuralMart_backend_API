from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ['email', 'first_name', 'last_name', 'phone_number', 'address', 'is_staff', 'is_active']
    list_filter = ['is_staff', 'is_active']
    search_fields = ['email']
    ordering = ['email']
    
    # Fieldsets for detailed user information
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'phone_number', 'address')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    # Add Fieldsets for user creation
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'first_name', 'last_name', 'phone_number', 'address', 'is_active', 'is_staff', 'is_superuser')}
        ),
    )

# Register the custom user model with the customized UserAdmin
admin.site.register(CustomUser, CustomUserAdmin)
