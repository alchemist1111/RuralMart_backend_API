from django.db import models
from django.contrib.auth.models import AbstractUser


ROLE_CHOICES = [
        ('customer', 'Customer'),
        ('farmer', 'Farmer'),
        ('artisan', 'Artisan'),
        ('admin', 'Admin'),
    ]

# Create your models here.
class CustomUser(AbstractUser):
    username = None  # Disable username field
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(unique=True, blank=False, null=False)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default='customer')
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    
    
    def __str__(self):
        return f'{self.email} ({self.get_role_display()})' 
    
    
    
# User profile class
class UserProfile(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    address = models.CharField(max_length=255, blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    
    def __str__(self):
        return f'Profile of {self.user.email}' 
