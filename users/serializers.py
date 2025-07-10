from rest_framework import serializers
from django.contrib.auth import password_validation
from allauth.account.models import EmailAddress
from .models import CustomUser

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    password_confirmation = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'password', 'password_confirmation']
        
    def validate(self, attrs):
        # Validate that passwords match
        if attrs['password'] != attrs['password_confirmation']:
            raise serializers.ValidationError("Passwords do not match.") 
        password_validation.validate_password(attrs['password'])  # Validate password strength
        return attrs
    
    def create(self, validated_data):
        # Remove password_confirmation as it's not part of the model
        validated_data.pop('password_confirmation', None)

        # Create the user with the provided data (excluding password confirmation)
        user = CustomUser.objects.create_user(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            email=validated_data['email'],
            phone_number=validated_data.get('phone_number', ''),
            password=validated_data['password'],
        )
        
        # Set the user as inactive until email is verified
        user.is_active = False
        user.save()
        
        # Create email address instance and send verification email
        EmailAddress.objects.create(user=user, email=user.email, verified=False)
        return user
