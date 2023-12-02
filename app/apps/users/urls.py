from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

from users.views import CreateUserView, VerifyAPIView, ResendVerifyCodeView, UpdateUserInformationView, \
    ChangeUserPhotoView, LoginView, LoginRefreshTokenView, LogoutView, ForgotPasswordView

urlpatterns = [
    path('login', LoginView.as_view(), name='login'),
    path('login/refresh', LoginRefreshTokenView.as_view(), name='login_refresh'),
    path('signup', CreateUserView.as_view(), name='signup'),
    path('logout', LogoutView.as_view(), name='logout'),
    path('forgot-password', ForgotPasswordView.as_view(), name='forgot_password'),
    path('verify', VerifyAPIView.as_view(), name='verify'),
    path('resend-code', ResendVerifyCodeView.as_view(), name='resend_code'),
    path('update', UpdateUserInformationView.as_view(), name='update'),
    path('change-photo', ChangeUserPhotoView.as_view(), name='change_photo'),
]