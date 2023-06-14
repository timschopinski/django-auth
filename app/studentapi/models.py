from django.db import models


class Student(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    index = models.IntegerField(db_index=True, unique=True)
    city = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.first_name} {self.last_name} {self.index}"

