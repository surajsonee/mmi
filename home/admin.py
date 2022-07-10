from django.contrib import admin
from .models import Membership, UserMembership, Subscription, MembershipDiscord, MembershipTV,MembershipMT5

# Register your models here.
admin.site.register(Membership)
admin.site.register(UserMembership)
admin.site.register(Subscription)
admin.site.register(MembershipDiscord)
admin.site.register(MembershipTV)
admin.site.register(MembershipMT5)