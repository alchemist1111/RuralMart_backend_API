from django.db import models
from django.contrib.auth.models import AbstractUser

# Custom user model inheriting from AbstractUser
class CustomUser(AbstractUser):
    username = None  # Disable username field
    
    # Required fields for the user model
    first_name = models.CharField(max_length=255, blank=False)
    last_name = models.CharField(max_length=255, blank=False)
    email = models.EmailField(unique=True, blank=False)
    
    # Custom fields
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    
    # Make username field equal to email
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']  # Required fields for user creation
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} <{self.email}>"
