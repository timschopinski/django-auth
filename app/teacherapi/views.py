from .models import Teacher
from .serializers import TeacherSerializer
from rest_framework import viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated


class TeacherModelViewSet(viewsets.ModelViewSet):
    queryset = Teacher.objects.all()
    serializer_class = TeacherSerializer
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]
