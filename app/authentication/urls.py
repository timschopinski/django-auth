from django.urls import path
from authentication.views import LoginView, RegisterView
from authentication.token import CustomAuthToken


urlpatterns = [
    path("gettoken/", CustomAuthToken.as_view()),
    path("login/", LoginView.as_view(), name="login"),
    path("register/", RegisterView.as_view(), name="register"),
]
