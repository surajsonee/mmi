import django
from django.db import models

# Create your models here.

from django.conf import settings
from django.db import models
from django.db.models.signals import post_save

from datetime import date, datetime
import time

from django.utils import timezone

import stripe
stripe.api_key = settings.STRIPE_SECRET_KEY


MEMBERSHIP_CHOICES = (
    ("Free", "Free"),
    ("MM Bundle Monthly","MMB1M"),
    ("MM Bundle Quarterly","MMB3M"),
    ("MM Bundle Semestral","MMB6M"),
    ("MM Bundle Yearly","MMB1Y")
)

class Membership(models.Model):
    slug= models.SlugField()
    m_type= models.CharField(choices=MEMBERSHIP_CHOICES, max_length=30, default="Free")
    m_price= models.IntegerField(default=0)
    stripe_plan_id= models.CharField(max_length=40,default="noplan")
    old_stripe_plan_id= models.CharField(max_length=40,default="nooldplan")

    def __str__(self):
        return self.m_type

    #def product(self):
    #    return self.product_set.all().order_by()

class UserMembership(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    
    stripe_customer_id = models.CharField(max_length=40)
    membership = models.ForeignKey(Membership, on_delete=models.SET_NULL, null=True)
    
    
    def __str__(self):
        return self.user.username

def post_save_usermembership_create(sender, instance, created, *args, **kwargs):
    
    user_membership, created = UserMembership.objects.get_or_create(
        user=instance)


    if user_membership.stripe_customer_id is None or user_membership.stripe_customer_id == '':
        new_customer_id = stripe.Customer.create(email=instance.email)
        free_membership = Membership.objects.filter(m_type='Free').first()

        user_membership.stripe_customer_id = new_customer_id['id']
        user_membership.membership = free_membership
        user_membership.save()


post_save.connect(post_save_usermembership_create,sender=settings.AUTH_USER_MODEL)

class Subscription(models.Model):
    user_membership = models.ForeignKey(UserMembership, on_delete=models.CASCADE)
    stripe_subscription_id = models.CharField(max_length=40,default="")
    sub_active = models.BooleanField(default=False)

    def __str__(self):
        return self.user_membership.user.username

    @property
    def get_created_date(self):
        sub = stripe.Subscription.retrieve(self.stripe_subscription_id)
        return datetime.fromtimestamp(sub.created)
    @property
    def get_next_billing_date(self):
        sub = stripe.Subscription.retrieve(self.stripe_subscription_id)
        return datetime.fromtimestamp(sub.current_period_end)

class MembershipDiscord(models.Model):
    membership = models.ForeignKey(Membership, on_delete=models.CASCADE)
    discord_private = models.BigIntegerField(max_length=50,default=0)

    def __str__(self):
        return self.membership.m_type

class MembershipTV(models.Model): 
    membership = models.ForeignKey(Membership, on_delete=models.CASCADE)
    tv_inviteonly = models.CharField(max_length=50,default="")

    def __str__(self):
        return self.membership.m_type

class MembershipMT5(models.Model):
    membership = models.ForeignKey(Membership, on_delete=models.CASCADE)
    mt5_ea_name = models.CharField(max_length=50,default="")
    is_mt5 = models.BooleanField(default=False)

    def __str__(self):
        return self.membership.m_type