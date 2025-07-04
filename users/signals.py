# users/signals.py

from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import CustomUser, UserProfile

# Signal to create a user profile when a CustomUser is created
@receiver(post_save, sender=CustomUser)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

# Signal to save the user profile when the CustomUser is saved
@receiver(post_save, sender=CustomUser)
def save_user_profile(sender, instance, **kwargs):
    instance.userprofile.save()

# Signal to delete the user profile when the CustomUser is deleted
@receiver(post_save, sender=CustomUser)
def delete_user_profile(sender, instance, **kwargs):
    try:
        instance.userprofile.delete()
    except UserProfile.DoesNotExist:
        pass