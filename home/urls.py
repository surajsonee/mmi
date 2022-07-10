from django.urls import path,include
from django.conf.urls.static import static
from django.conf import settings

#from .views import HomePage
from . import views

app_name = "home"

urlpatterns = [

    path('', views.HomePage, name="home"),
    #path('products', views.ProductsPage, name="products"),
    path('products_checkout', views.ProductsCheckout, name="products_checkout"),
    path('products_transaction/<subscription_id>', views.ProductsTransaction, name="products_transaction"),
    path('about', views.AboutUsPage, name="about"),
    path('profile', views.ProfilePage, name="profile"),
    path('profile/update', views.ProfileUpdate, name="profile_update"),
    path('profile/migrate_sub', views.ProfileMigrateSub, name="profile_migrate_sub"),
    path('profile/cancel_sub', views.ProfileCancelSub, name="profile_cancel_sub"),
    
    path('profile/discord_auth', views.DiscordAuth, name="discord_auth"),
    path('profile/tv_auth', views.TvAuth, name="tv_auth"),
    path('profile/mt5_license', views.MT5Licence, name="mt5_license"),
    path('profile/discord_authc', views.DiscordAuthC, name="discord_authc"),
    path('profile/get_ctable', views.AdCustomerTable, name="profile_ad_ctable"),
    path('algo_getting_started', views.AlgoGSPage, name="algo_gs"),
    path('algo_mmsigma', views.AlgoMMSIGMAPage, name="algo_mmsigma"),
    
    path('auth_f/', include('auth_f.urls')),
    
    

] 
