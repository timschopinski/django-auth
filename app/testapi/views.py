from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser, IsAuthenticatedOrReadOnly, \
    DjangoModelPermissions, DjangoModelPermissionsOrAnonReadOnly, BasePermission


class OnlyAdminView(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAdminUser]

    @staticmethod
    def get(request: Request):
        return Response("Hello Admin")


