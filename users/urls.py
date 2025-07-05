# File: users/urls.py
from django.urls import path
from .views import RegisterView, LoginView, PasswordResetRequestView, PasswordResetConfirmView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('password_reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]
