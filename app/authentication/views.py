from django.contrib.auth import login
from rest_framework import permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from authentication.serializers import LoginSerializer, RegisterSerializer


class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = LoginSerializer(data=self.request.data, context={'request': self.request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        return Response(None, status=status.HTTP_202_ACCEPTED)


class RegisterView(APIView):

    def post(self, request):
        serializer = RegisterSerializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(None, status=status.HTTP_201_CREATED)
