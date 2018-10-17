from django.db import models

# Create your models here.
class User(models.Model):
    name = models.CharField(max_length=20)
    password = models.CharField(max_length=200)
    salt = models.BinaryField(max_length=32)
    cookie = models.BinaryField(max_length = 32)
    admin = models.BooleanField()