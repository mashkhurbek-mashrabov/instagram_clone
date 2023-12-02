from django.urls import path

from users.views import CreateUserView, VerifyAPIView, ResendVerifyCodeView, UpdateUserInformationView, \
    ChangeUserPhotoView

urlpatterns = [
    path('signup', CreateUserView.as_view(), name='signup'),
    path('verify', VerifyAPIView.as_view(), name='verify'),
    path('resend-code', ResendVerifyCodeView.as_view(), name='resend_code'),
    path('update', UpdateUserInformationView.as_view(), name='update'),
    path('change-photo', ChangeUserPhotoView.as_view(), name='change_photo'),
]