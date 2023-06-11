from django.urls.conf import path
from testapi import views


urlpatterns = [
    path("only-admin/", views.OnlyAdminView.as_view(), name="only-admin"),
    path("throttling/", views.ThrottleView.as_view(), name="throttling"),
]
