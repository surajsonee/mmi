from django.urls import path,include


#from .views import HomePage
from . import views

app_name = "auth_f"

urlpatterns = [

    path('login', views.LoginPage, name="login"),
    path('register', views.RegisterPage, name="register"),
    path("logout", views.Logout, name='logout'),
    path('activate_user/<uidb64>/<token>',
         views.ActivateUser, name='activate'),
] 