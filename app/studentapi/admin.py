from django.contrib import admin
from studentapi.models import Student


class StudentAdmin(admin.ModelAdmin):
    search_fields = ("first_name", "index", "last_name")


admin.site.register(Student, StudentAdmin)
