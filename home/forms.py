
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from auth_f.models import User


class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'password', 'email', 'tv_acct', 'mt5_acct']