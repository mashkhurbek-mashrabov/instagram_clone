from django.urls import path

from users.views import CreateUserView, VerifyAPIView, ResendVerifyCodeView

urlpatterns = [
    path('signup', CreateUserView.as_view(), name='signup'),
    path('verify', VerifyAPIView.as_view(), name='verify'),
    path('resend-code', ResendVerifyCodeView.as_view(), name='resend_code'),
]