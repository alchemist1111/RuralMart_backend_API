from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from .serializers import RegisterSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.exceptions import ValidationError
from django.contrib.auth import password_validation
from django.core.mail import send_mail
from rest_framework.permissions import AllowAny

# Get the correct user model
User = get_user_model()

# Register View
class RegisterView(APIView):
    """
    View to handle user registration.
    """
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            # Save the user instance after validation
            serializer.save()
            # Return a response with a success message
            message = (
                "User registered successfully. Please check your email to verify your account."
            )
            return Response({"message": message}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Login View
class LoginView(APIView):
    """
    View to handle user login and JWT token generation.
    """
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # Authenticate user using email and password
        user = authenticate(request, email=email, password=password)

        if user is None:
            return Response({"error": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_active:
            return Response({"error": "Account is inactive. Please verify your email."}, status=status.HTTP_403_FORBIDDEN)

        # Create JWT tokens for the user
        refresh = RefreshToken.for_user(user)
        
        # Return the response with the tokens and user info
        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": {
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "role": user.role,
            }
        }, status=status.HTTP_200_OK)

# Password Reset Request View
class PasswordResetRequestView(APIView):
    """
    View to handle password reset requests.
    """
    def post(self, request):
        email = request.data.get('email')

        # Check if the email exists in the system
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Avoid revealing if email exists or not for security reasons
            return Response({"detail": "If this email is registered, a reset link will be sent."}, status=status.HTTP_200_OK)

        # Generate token for password reset
        token = default_token_generator.make_token(user)

        # URL-safe encode the user ID
        uid = urlsafe_base64_encode(user.pk.encode())

        # Construct the reset URL
        reset_url = f'http://example.com/reset/{uid}/{token}'

        # Construct the email content (plain text)
        subject = "Password Reset Request"
        message = f"Hello {user.first_name},\n\n" \
                  f"Click the link below to reset your password:\n" \
                  f"{reset_url}\n\n" \
                  f"If you did not request a password reset, please ignore this email."

        # Send reset password email
        send_mail(
            subject,
            message,
            'from@example.com',
            [email],
            fail_silently=False,
        )

        return Response({"message": "If this email is registered, a reset link will be sent."}, status=status.HTTP_200_OK)

# Password Reset Confirm View
class PasswordResetConfirmView(APIView):
    """
    View to handle password reset confirmation.
    """
    def post(self, request, uidb64, token):
        # Decode the uid from base64
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, User.DoesNotExist):
            return Response({"detail": "Invalid token or user."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the token is valid
        if not default_token_generator.check_token(user, token):
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

        # Get new password from request
        new_password = request.data.get('new_password')
        if not new_password:
            return Response({"detail": "New password is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate password using Django's built-in password validation system
        try:
            password_validation.validate_password(new_password, user)  # Check the new password
            user.set_password(new_password)  # Set the new password
            user.save()  # Save the user instance with the new password
        except ValidationError as e:
            return Response({"detail": f"Password validation error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        # Return success message
        message = (
            "Password reset successful. You can now log in with your new password."
        )
        return Response({"message": message}, status=status.HTTP_200_OK)
