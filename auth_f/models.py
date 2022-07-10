from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    is_email_verified = models.BooleanField(default=False)
    tv_acct = models.CharField(max_length=30, default="none")
    mt5_acct = models.CharField(max_length=30, default="none")
    mt5_bk = models.CharField(max_length=50, default="none")
    discord_acct = models.BigIntegerField (default=0 )
    discord_at = models.CharField(max_length=50, default="none")
    tv_ok = models.BooleanField(default=False)
    mt5_ok = models.BooleanField(default=False)

    def __str__(self):
        return self.email