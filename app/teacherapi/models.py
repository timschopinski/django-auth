from django.db import models


class Teacher(models.Model):
    TITLE_CHOICES = (
        ('engineer', 'Engineer'),
        ('bachelor', 'Bachelor'),
        ('master', 'Master'),
        ('phd', 'PhD'),
        ('professor', 'Professor'),
    )

    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    title = models.CharField(max_length=20, choices=TITLE_CHOICES)
    city = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.title} {self.first_name} {self.last_name}"
