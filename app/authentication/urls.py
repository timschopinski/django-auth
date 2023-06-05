from django.urls import path
from authentication.views import LoginView
from authentication.token import CustomAuthToken


urlpatterns = [
    path("gettoken/", CustomAuthToken.as_view()),
    path("login/", LoginView.as_view(), name="login"),
]
