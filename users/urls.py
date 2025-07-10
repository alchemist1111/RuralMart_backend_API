# File: users/urls.py
from django.urls import path
from .views import RegisterView, LoginView, PasswordResetRequestView, PasswordResetConfirmView, EmailVerificationView, DeleteUserByIdView, UserListView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('users/', UserListView.as_view(), name='user-list'),
    path('delete_user/<int:user_id>/', DeleteUserByIdView.as_view(), name='delete-user-by-id'),
    path('verify-email/<uidb64>/<token>/', EmailVerificationView.as_view(), name='email-verify'),
    path('password_reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]
