from django.contrib import admin
from teacherapi.models import Teacher


class TeacherAdmin(admin.ModelAdmin):
    search_fields = ("first_name", "last_name")


admin.site.register(Teacher, TeacherAdmin)
