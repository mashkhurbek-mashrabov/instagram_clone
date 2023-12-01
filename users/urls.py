from django.urls import path

from users.views import CreateUserView, VerifyAPIView

urlpatterns = [
    path('signup', CreateUserView.as_view(), name='signup'),
    path('verify', VerifyAPIView.as_view(), name='verify'),
]