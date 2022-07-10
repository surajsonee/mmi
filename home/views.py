from calendar import month
import time
from django import conf
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render, redirect
from django.urls import reverse
from django.contrib.auth.decorators import login_required

from auth_f.views import EmailThread

from .models import Membership, MembershipMT5, UserMembership, Subscription, MembershipDiscord, MembershipTV
from auth_f.models import User
from .forms import UserUpdateForm
from django.contrib import messages
import zipfile
from validate_email import validate_email
from django.conf import settings
import stripe
stripe.api_key = settings.STRIPE_SECRET_KEY

import requests
from dateutil.relativedelta import relativedelta
from datetime import date
from decouple import config
from django.core import serializers
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from auth_f.utils import generate_token
from django.core.mail import EmailMessage
from django.conf import settings
# region Selenium imports
from selenium import webdriver
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver import FirefoxOptions
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
import os
import re
from selenium.common.exceptions import NoSuchElementException,InvalidArgumentException,StaleElementReferenceException,TimeoutException
from datetime import datetime
from time import sleep
import json
from typing import List


#endregion
import os
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler

import socket

#region MT5 Licencing classes
class socketserver:
    def __init__(self, address = '', port = 9090):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.address = address
        self.port = port
        self.sock.bind((self.address, self.port))
        self.cummdata = ''
        
    def recvmsg(self):
        self.sock.listen(1)
        self.conn, self.addr = self.sock.accept()
        print('connected to', self.addr)
        self.cummdata = ''

    def __del__(self):
        self.sock.close()

#endregion



#region funcs

def get_user_membership(request):
    user_membership_qs = UserMembership.objects.filter(user=request.user)
    if user_membership_qs.exists():
        return user_membership_qs.first()
    return None


def get_user_subscription(request):
    user_subscription_qs = Subscription.objects.filter(
        user_membership=get_user_membership(request))
    if user_subscription_qs.exists():
        user_subscription = user_subscription_qs.first()
        return user_subscription
    return None


def get_selected_membership(request):
    membership_type = request.session['selected_membership_type']
    selected_membership_qs = Membership.objects.filter(
        m_type=membership_type)
    if selected_membership_qs.exists():
        return selected_membership_qs.first()
    return None

#endregion


#region APP views
def HomePage(request):
    print(request.method)
    if request.method == 'POST':
        fm=""
        if 'btn_mmbundle' in request.POST:
            ddv_1 = request.POST.get('dd_mmbundle')
            if ddv_1 == "1": fm =  "MM Bundle 1M"
            elif ddv_1 == "2": fm =  "MM Bundle 1M"
            elif ddv_1 == "3": fm =  "MM Bundle 3M"
            elif ddv_1 == "4": fm =  "MM Bundle 6M"
            elif ddv_1 == "5": fm =  "MM Bundle 1Y"
        elif 'btn_mmsuite' in request.POST:
            ddv_2 = request.POST.get('dd_mmsuite')
            if ddv_2 == "1": fm =  "MM Bundle 1M"
            elif ddv_2 == "2": fm =  "MM Bundle 1M"
            elif ddv_2 == "3": fm =  "MM Bundle 3M"
            elif ddv_2 == "4": fm =  "MM Bundle 6M"
            elif ddv_2 == "5": fm =  "MM Bundle 1Y"
        elif 'btn_mmsigma' in request.POST:
            ddv_3 = request.POST.get('dd_mmsigma')
            if ddv_3 == "1": fm =  "MM Bundle 1M"
            elif ddv_3 == "2": fm =  "MM Bundle 1M"
            elif ddv_3 == "3": fm =  "MM Bundle 3M"
            elif ddv_3 == "4": fm =  "MM Bundle 6M"
            elif ddv_3 == "5": fm =  "MM Bundle 1Y"
        
        print(fm)
        request.session['selected_membership_type'] = Membership.objects.get(slug="MMB1M").m_type
        return HttpResponseRedirect(reverse("home:products_checkout"))
        
    return(render( request , "home/home.html"))



@login_required
def ProductsCheckout(request):
    user_membership = get_user_membership(request)
    try:
        selected_membership = get_selected_membership(request)
    except:
        return redirect(reverse("home:home"))
    publishKey = settings.STRIPE_PUBLISHABLE_KEY
    print(request.method)
    if request.method == "POST":
        print(request.POST)
        token=""
        i=0
        while i<len(request.POST['stripeToken']):
            token += request.POST['stripeToken'][i]
            i=i+1
        # UPDATE FOR STRIPE API CHANGE 2018-05-21

        '''
        First we need to add the source for the customer
        '''
        customer = stripe.Customer.retrieve(user_membership.stripe_customer_id)
        customer.source = token # 4242424242424242
        customer.save()

        '''
        Now we can create the subscription using only the customer as we don't need to pass their
        credit card source anymore
        '''

        subscription = stripe.Subscription.create(
            customer=user_membership.stripe_customer_id,
            items=[
                { "plan": selected_membership.stripe_plan_id },
            ]
        )
        return redirect(reverse('home:products_transaction',
                                kwargs={
                                    'subscription_id': subscription.id
                                }))


    context = {
        'publishKey': publishKey,
        'selected_membership': selected_membership
    }



    return(render( request , "home/products_checkout.html", context))

@login_required
def ProductsTransaction(request, subscription_id):
    user_membership = get_user_membership(request)
    selected_membership = get_selected_membership(request)
    user_membership.membership = selected_membership
    user_membership.save()

    sub, created = Subscription.objects.get_or_create(
        user_membership=user_membership)
    sub.stripe_subscription_id = subscription_id
    sub.sub_active = True
    sub.save()

    try:
        del request.session['selected_membership_type']
    except:
        pass
    
    

    messages.info(request, 'Successfully created {} membership'.format(
        selected_membership))
    
    #for n in range(20):
    #    print("setup loop",n)
    #    try:
    #        options = webdriver.ChromeOptions()
    #
    #        options.add_argument(f"user-data-dir=C:\Users\giuli\newMMI\mmi\chrome_d\data{n}")
    #        # options.add_argument("--headless") # Runs Chrome in headless mode.
    #        # options.add_argument('--no-sandbox') # Bypass OS security model
    #        # options.add_argument('--disable-gpu')
    #
    #        driver = webdriver.Chrome(executable_path=os.path.abspath("./chromedriver.exe"),options=options)
    #        driver.implicitly_wait(8)
    #        sleep(3)
    #        driver.get("https://www.tradingview.com/")
    #        print("setup completed")
    #        tv_login(driver=driver)
    #        tv_get_all_charts(driver=driver)
    #        break
    #    except InvalidArgumentException:
    #        print("dir in use... changing dir")
    #        if driver:
    #            driver.quit()
    #            driver = None

    return redirect(reverse('home:home'))


def ProductsPage(request):
    return(render( request , "home/products.html"))


def AboutUsPage(request):
    return(render( request , "home/about_us.html"))

@login_required
def ProfilePage(request):
    user_membership = get_user_membership(request)
    user_subscription = get_user_subscription(request)
    is_mt5 = False
    if MembershipMT5.objects.filter(membership=user_membership.membership).exists():
        is_mt5 = MembershipMT5.objects.filter(membership=user_membership.membership).first().is_mt5
    context = {
        'user_membership': user_membership,
        'user_subscription': user_subscription,
        'user': request.user,
        'is_mt5': is_mt5
    }
    return render(request, "home/profile.html", context)


@login_required
def ProfileMigrateSub(request):
    if(request.method=="POST"):

        _id = request.user.id
        u_id = get_user_membership(request)
        user_membership = get_user_membership(request)
        old_membership_raw = request.POST.get("old_membership")
        print(stripe.api_key)
        print(old_membership_raw)
        um = Membership.objects.filter(m_type=old_membership_raw).first()
        old_membership = Membership.objects.filter(m_type=old_membership_raw).first().old_stripe_plan_id
        new_membership = Membership.objects.filter(m_type=old_membership_raw).first().stripe_plan_id

        context = {'has_error': False, 'data': request.POST}
        stripe_cid = request.POST.get('stripe_cid')
        data = stripe.Subscription.list()
        oldsub = stripe.Subscription.retrieve(
            stripe_cid,
            
        )   
        print(oldsub)
        _cust = oldsub['customer']
        _oldsubid = oldsub['id']
        custsub=""
        is_moresubs = data['data'][0]['items']['has_more']
        
        subs_arr = data['data'][0]['items']['data']
        if _oldsubid == stripe_cid:
            
            oldsub_ends = oldsub["current_period_end"] 
            #trial = (datetime.fromtimestamp(oldsub_ends) - date.today()).days
            #print(trial)
            subcanc_status=""
            try:
                subcanc_status=stripe.Subscription.delete(
                    oldsub,
                )
            except:
                messages.info(request,"Old Subscription Cancellation went wrong. Migration to New Subscription Aborted. Contact Support.")
            print(subcanc_status["status"])
            if(subcanc_status["status"]=="canceled"):
                
                try:
                    subscription = stripe.Subscription.create(
                        customer=_cust,
                        items=[
                            { "plan": new_membership },
                        ],
                        billing_cycle_anchor=oldsub_ends,
                        trial_end=oldsub_ends,
                    )

                    
                    user_membership.membership=um
                    user_membership.stripe_customer_id = _cust
                    user_membership.save()

                    print(u_id)
                    if(Subscription.objects.filter(pk=_id).exists()):
                        sub = Subscription.objects.get(user_membership=_id)
                        sub.sub_active=True
                        sub.stripe_subscription_id = subscription['id']
                        sub.save()
                    else:
                        sub = Subscription.objects.get_or_create(user_membership_id=_id,sub_active=True,stripe_subscription_id = subscription['id'])
                        #sub.save()


                        messages.info(request,"Migration Completed. New Subscription Active. Details have been updated.")

                        return redirect(reverse('home:profile'))
                        
                except:
                    messages.info(request,"Something went wrong with migration. Contact Support. No Sub Active.")
        


    return render(request, 'home/profile_migrate_sub.html')
@login_required
def ProfileUpdate(request):
    if request.method == 'POST':
        context = {'has_error': False, 'data': request.POST}
        email = request.POST.get('email')
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        tv_acct = request.POST.get('tv_acct')
        mt5_acct = request.POST.get('mt5_acct')
        mt5_bk = request.POST.get('mt5_bk')
        discord_acct = request.POST.get('discord_acct')

        current_user = request.user
        u_id = current_user.id

        print(username)
        if password != None:
            if len(password) != 0:

                if len(password) < 6:
                    messages.add_message(request, messages.ERROR,'Update Failed: Password should be at least 6 characters')
                    context['has_error'] = True

                if password != password2:
                    messages.add_message(request, messages.ERROR,'Update Failed: Password mismatch')
                    context['has_error'] = True

                if not context['has_error']:
                    User.objects.filter(pk=u_id).update(password=password)
        if username != None:
            if len(username)!=0:
                
                if User.objects.filter(username=username).exists():
                    messages.add_message(request, messages.ERROR,'Update Failed: Username is taken, choose another one')
                    context['has_error'] = True

                    return render(request, 'home/profile.html', context, status=409)
                else:
                    User.objects.filter(pk=u_id).update(username=username)

        if email != None:
            if len(email)!=0:
                
                if User.objects.filter(email=email).exists():
                    messages.add_message(request, messages.ERROR,'Update Failed: Email is taken, choose another one')
                    context['has_error'] = True

                    return render(request, 'home/profile.html', context, status=409)
                elif not validate_email(email):
                    messages.add_message(request, messages.ERROR,'Update Failed: Enter a valid email address')
                    context['has_error'] = True
                else:
                    User.objects.filter(pk=u_id).update(email=email)

        if mt5_acct != None:
            if len(mt5_acct)!=0:
                User.objects.filter(pk=u_id).update(mt5_acct=mt5_acct)

        if mt5_bk != None:
            if len(mt5_bk)!=0:
                print(mt5_bk)
                User.objects.filter(pk=u_id).update(mt5_bk=mt5_bk)

        if tv_acct != None:
            if len(tv_acct)!=0:
                User.objects.filter(pk=u_id).update(tv_acct=tv_acct)

        if discord_acct != None:
            if len(discord_acct)!=0:
                User.objects.filter(pk=u_id).update(discord_acct=discord_acct)

        if not context['has_error']:
            
            messages.add_message(request, messages.SUCCESS,'Update Done')
            return redirect('home:profile')

    return render(request, 'home/profile_update.html')



@login_required
def AdCustomerTable(request):
    
    all_cust = User.objects.all()
    context = {
        'all_cust': all_cust
    }

    return render(request, 'home/profile_ad_ctable.html', context=context)


def AlgoGSPage(request):
    return(render( request , "home/algo/algo_gs.html"))


def AlgoMMSIGMAPage(request):
    return(render( request , "home/algo/algo_mmsigma.html"))


#region Discord Functions

def add_to_guild(access_token, userID, user_membership):
    url = config("API_ENDPOINT")+"/guilds/"+str(config("DISCORD_SERVER_ID"))+"/members/"+str(userID)
    discord_priv = []        
    for e in MembershipDiscord.objects.all():
        if MembershipDiscord.objects.filter(membership=user_membership).exists():
            discord_priv.append(MembershipDiscord.objects.filter(membership=user_membership).first().discord_private)
        
    print(discord_priv)
    
    botToken = config("DISCORD_BOT_TOKEN")
    data = {
        "access_token" : access_token,
        "roles": discord_priv
    }
    headers = {
        "Authorization" : f"Bot {botToken}",
        'Content-Type': 'application/json'

    }
    response = requests.put(url=url, headers=headers, json=data)
    print(response)
    print(response.text)

#endregion

def DiscordAuth(request):
    discord_auth_url = "https://discord.com/api/oauth2/authorize?response_type=code&client_id="+config("CLIENT_ID")+"&scope=identify%20guilds.join&state=15773059ghq9183habn&redirect_uri="+config("REDIRECT_URI")+"&prompt=consent"
    return redirect(discord_auth_url)
    
def DiscordAuthC(request): 
        
    payload={
        "client_id":config("CLIENT_ID"),
        "redirect_uri":config("REDIRECT_URI"),
        "response_type":"code",
        "scope":"identify"
    }

    #discord_auth_url = "https://discord.com/api/oauth2/authorize?response_type=code&client_id="+config("CLIENT_ID")+"&scope=identify%20guilds.join&state=15773059ghq9183habn&redirect_uri="+config("REDIRECT_URI")+"&prompt=consent"
    #return(redirect(discord_auth_url))
    code = request.GET.get('code')
    access_token = exchange_code(request.user.id,code)
    add_to_guild(access_token=access_token, userID=request.user.discord_acct, user_membership=get_user_membership(request).membership.id)


    #return JsonResponse({"mdg":"discord auth"})
    
    return redirect(reverse('home:profile'))

def exchange_code(u_id,code: str):
    
    data = {
        'client_id': config("CLIENT_ID"),
        'client_secret': config("CLIENT_SECRET"),
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': config("REDIRECT_URI"),
        'scope':'identify'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    r = requests.post(config("API_ENDPOINT") + '/oauth2/token', data=data, headers=headers)
    print(r)
    r.raise_for_status()
    credentials = r.json()
    print(credentials)
    access_token = credentials["access_token"]
    r = requests.get("https://discord.com/api/v10/users/@me", headers={
        "Authorization":"Bearer %s " % access_token
    })
    user = r.json()
    print(user)
    if len(access_token)!=0:
        User.objects.filter(pk=u_id).update(discord_at=access_token)
    return access_token
#endregion



def TvAuth(request):
    print(request.method)
    if request.method == "GET":

        driver = tv_driver()
        wait = WebDriverWait(driver, 5)
        if driver != None:
            try:
                tv_login(driver=driver,wait=wait)
            except: 
                messages.info(request,"Error In Backend TV Login")
            tv_charts=tv_get_all_charts(driver=driver)

            user_membership = get_user_membership(request)
            tv_links=[]
            try:
                for e in MembershipTV.objects.all():
                    if MembershipTV.objects.filter(membership=user_membership.membership).exists():
                        tv_indi = MembershipTV.objects.filter(membership=user_membership.membership).first().tv_inviteonly
                        tv_links.append(tv_get_chart_link_from_name(driver, tv_indi))
            except:
                messages.info(request,"Error In Backend TV Indicators Scraping")
            print(tv_links)    
            for indi in tv_links:
                print(indi['link'])
                print(get_user_subscription(request).get_next_billing_date)
                try:
                    tv_add_members(request=request,wait=wait,driver=driver,username=request.user.tv_acct, sub_expire = get_user_subscription(request).get_next_billing_date, link=indi['link'])
                except:    
                    messages.info(request,"Error In Backend TV Adding Members")
        return redirect(reverse('home:profile'))
    return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

    #     login_username = "Dallionking@gmail.com"

    #     login_password = "LoneSigma2542"

    #     username = "thealgorithmictrader"

    #     expiration_date = "2022-05-30"

    #     lifetime_plan = True


    #     opts = FirefoxOptions()
    #     opts.add_argument("--headless")

    #     driver = webdriver.Firefox(options=opts)
    #     driver.get("https://www.tradingview.com/#signin")

    #     driver.maximize_window()
    #     time.sleep(5)
    #     driver.close()
    # return HttpResponse({"msg:success"})
        
    



def tv_driver():

    #options = Options()
    #options.binary_location = os.environ.get('GOOGLE_CHROME_BIN')
    #options.add_argument('--headless')
    #options.add_argument('--disable-gpu')
    #options.add_argument('--no-sandbox')
    #options.add_argument('--disable-dev-shm-usage')        
    #options.add_argument('--remote-debugging-port=9222')
    #f"user-data-dir=C:\\Users\\HP\\Desktop\\Project\\ChromeData{n}"
    #return webdriver.Chrome(executable_path=str(os.environ.get('CHROMEDRIVER_PATH')), chrome_options=options)


    print("setup start")
        
    for n in range(20):
        print("setup loop",n)
        try:
            opts = FirefoxOptions()
            opts.add_argument("--headless")

            driver = webdriver.Firefox(options=opts)
            # opts.add_argument("--headless")

            # options.add_argument("--headless") # Runs Chrome in headless mode.
            # options.add_argument('--no-sandbox') # Bypass OS security model
            # options.add_argument('--disable-gpu')

            # driver = webdriver.webdriver.Firefox(options=opts)
            print(driver)
            driver.implicitly_wait(8)
            sleep(3)
            
            print("setup completed")
            break
            
        except InvalidArgumentException:
            print("dir in use... changing dir")
            if driver:
                driver.quit()
                driver = None
    
    return driver
def is_login(driver):
    try:
        
        src = driver.find_element_by_css_selector(".tv-header__user-menu-button.tv-header__user-menu-button--logged.js-header-user-menu-button img").get_attribute("src")
        return bool(src)
    except Exception as e:
        
        return False


months = {
    "1":"January",
    "2":"February",
    "3":"March",
    "4":"April",
    "5":"May",
    "6":"June",
    "7":"July",
    "8":"August",
    "9":"September",
    "10":"October",
    "11":"November",
    "12":"December"

}

def tv_select_date(driver,wait,date:str=None):
        """[summary]
        date selector 
        not date input must be on the dom
        Args:
            date (str, optional): [format 'yyyy-mm-dd']. Defaults to None.
        """
        print("inside select date")
        end_date = date
        start_date = datetime.today()

        months = (end_date.year - start_date.year) * 12 + (end_date.month - start_date.month)
        print(months)
        
        picker=wait.until(EC.element_to_be_clickable((By.XPATH, './/*[@id="overlap-manager-root"]/div/div/div[1]/div/div[2]/div/div/span/span[2]'))).click()
        
        i=0
        while i<months:
            months_slider = wait.until(EC.element_to_be_clickable((By.XPATH, './/*[@id="overlap-manager-root"]/div/div/div[2]/div/span/div/div/div[1]/span[2]'))).click()
            i+=1
        
        month_check = wait.until(EC.element_to_be_clickable((By.CLASS_NAME, 'title-U9DgB4FB')))
        comparer = str(date.strftime("%B")) + " " + str(date.year) 
        print(month_check.get_attribute('innerHTML'))
        print(comparer)
        if month_check.get_attribute('innerHTML') == comparer:
            #weeks = wait.until(EC.visibility_of_element_located((By.CLASS_NAME, 'weeks-U9DgB4FB')))
            #//*[@id="overlap-manager-root"]/div/div/div[2]/div/span/div/div/div[2]/div[2]/div[1]/span[1]
            print('span[data-day="{}"]'.format(str(datetime.strftime(end_date, '%Y-%m-%d'))))
            dayselect = driver.find_element_by_css_selector('span[data-day="{}"]'.format(str(datetime.strftime(end_date, '%Y-%m-%d'))))
            day_selector = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'span[data-day="{}"]'.format(str(datetime.strftime(end_date, '%Y-%m-%d')))))).click()


            checkbox = driver.find_element_by_css_selector('input[type="checkbox"]')
            #checkbox_label = checkbox.find_element_by_xpath('..')
            if checkbox.get_attribute('checked'):
                #checkbox_label.click()    
                wait.until(EC.element_to_be_clickable((By.XPATH, './/*[@id="overlap-manager-root"]/div/div/div[1]/div/div[2]/label[2]/span[1]/span'))).click()
        
        print(str(datetime.strftime(datetime.today(), '%Y-%m-%d')))
        
        #picker=driver.find_element_by_css_selector('input[value="{}"]'.format(str()))
        #picker=driver.find_element_by_css_selector('#overlap-manager-root > div > div > div.dialog-hxnnZcZ6.dialog-HExheUfY.dialog-Nh5Cqdeo.rounded-Nh5Cqdeo.shadowed-Nh5Cqdeo > div > div.container-dv1LvhyQ > div > div > span > span.inner-slot-QpAAIiaV.inner-middle-slot-QpAAIiaV > input')
        #picker.clear()
        #print(datetime.strftime(date, '%Y-%m-%d'))
        #picker.send_keys(str())
        #picker.click()
        #print('input[value="{}"]'.format(str(datetime.strftime(date, '%Y-%m-%d'))))
        #time.sleep(2)
        print("success")
    
def tv_login(driver,wait):
    driver.implicitly_wait(8)
    print("login()")
    if not driver.current_url in "https://www.tradingview.com/#signin":
        print("go to login link")
        driver.get("https://www.tradingview.com/#signin")

    print("is login method ",is_login(driver=driver))
    if not is_login(driver=driver):
    # if True:
        #     print("1")
        #     print("2")
        # 2 | setWindowSize | 1354x728 | 
        
        driver.set_window_size(1354, 728)
        # 3 | click | css=.tv-header__user-menu-button > svg | 
        
        driver.find_element(By.CSS_SELECTOR, ".i-clearfix").click()
        # 4 | click | css=.labelRow-2IihgTnv:nth-child(2) > .label-2IihgTnv | 
        
        
        email_input = driver.find_element_by_css_selector("input[autocomplete='username']")
        
        pwd_input = driver.find_element_by_css_selector("input[autocomplete='current-password']")
        
        btn_login = driver.find_element_by_xpath("//button[@type='submit']").click()
        email_input.clear()
        email_input.send_keys(config("TV_USERNAME"))
        pwd_input.clear()
        pwd_input.send_keys(config("TV_PASSWORD"),Keys.RETURN)
        
        #WebDriverWait(driver, 8).until(EC.visibility_of_element_located((By.XPATH, "//input[autocomplete='current-password']"))).send_keys(config("TV_PASSWORD"))
        wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, 'button[type="submit"]'))).click()
        
        print("login ends fine")
    

def tv_add_members(request, wait, driver, username, sub_expire, link:str=str()):
    """[summary]
    data = [
        {
            username:str,
            date:Optional[str] -> format 'yyyy-mm-dd'
        },
        ...
    ]
    Args:
        link (str, optional): [description]. Defaults to str().
        data (List[dict], optional): [description]. Defaults to [].
    """
    
    if link not in driver.current_url:
        driver.get(link)

        
        
        wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "body > div:nth-child(13) > div > div > div > article > div > div > div > button.acceptAll-W4Y0hWcd.button-YKkCvwjV.size-xsmall-YKkCvwjV.color-brand-YKkCvwjV.variant-primary-YKkCvwjV"))).click()

        wait.until(EC.element_to_be_clickable((By.XPATH, "./html/body/div[3]/div[4]/div/div/div[1]/div[10]/div[7]/button[2]"))).click()
        driver.find_element_by_css_selector("button[data-name='manage-access']").click()
        #tv-social-stats__text tv-social-stats__text--checked
        #wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, '.tv-dialog')))
        
        wait.until(EC.element_to_be_clickable((By.XPATH, './/*[@id="overlap-manager-root"]/div/div/div[1]/div/div[2]/div/div/div/div/div/button[2]'))).click()
        
        add_user = driver.find_element_by_css_selector("input[data-role='search']")
        add_user.clear()
        
        user_header=username[:2]
        print(user_header)
        check_user = 'div[data-username="{}"]'.format(username)
        usr_src=user_header
        add_user.send_keys(user_header)
        current_first=""
        try:
            current_first=wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, check_user)))
            if current_first.get_attribute("data-username")!=username:
                add_user.clear()
        except:
            add_user.clear()
        if current_first!=username:
            user_body=user_header
            i=2
            while i < len(username)-2:
                
                user_body+=username[i]
                add_user.send_keys(user_body)
                
                current_first=""
                try:
                    current_first=wait.until(EC.visibility_of_element_located((By.CSS_SELECTOR, check_user)))
                    total_list = driver.find_element_by_class_name("title-PLu464zm").text
                    print(current_first.get_attribute("data-username"))
                    print(total_list)
                    print(total_list[0])
                    if current_first.get_attribute("data-username")==username and total_list[0]=="1":
                        break
                    else:
                        add_user.clear()
                except:
                    add_user.clear()

                i+=1

        time.sleep(2)
        
        #ActionChains(driver).move_to_element(wait.until(EC.element_to_be_clickable((By.XPATH, './/*[@id="overlap-manager-root"]/div/div/div[1]/div/div[5]/div[2]/div/div/div/div[2]/span')))).click().perform()
        #for i in range(8):
        #    ActionChains(driver).send_keys(Keys.TAB).perform() #tab until element is selected
        #ActionChains(driver).send_keys(Keys.ENTER).perform() #press enter to "click" on it
        #driver.execute_script("arguments[0].click();", )
        #WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.CSS_SELECTOR, 'div[data-name="manage-access-dialog"]')))
        #WebDriverWait(driver, 8).until(EC.element_to_be_clickable((By.XPATH, './/*[@id="overlap-manager-root"]/div/div/div[1]/div/div[5]/div[2]/div/div/div/div[2]/span')))
        time.sleep(2)
        WebDriverWait(driver, 8).until(EC.element_to_be_clickable((By.XPATH, './/*[@id="overlap-manager-root"]/div/div/div[1]/div/div[5]/div[2]/div/div/div/div[2]/span'))).click()
        """ try:
            driver.implicitly_wait(2)
            print("in the try")
            text = driver.find_element_by_css_selector(".title-30_lleAw").text
            find = re.findall(r"(\d+) users","108 users have access",re.I)
            if find:
                total = int(find[0])
                count = total/12

                for _ in range(int(count)):
                    sleep(0.7)
                    if username in [element.get_attribute("data-username") for element in driver.find_elements_by_css_selector(".item-2O1-TdRo")]:
                        
                        print("user exist already")
                        driver.find_element_by_css_selector(f"[data-username='{username}'] span[data-name='manage-access-dialog-item-remove-button']").click()
                        break
                    last_element = driver.find_elements_by_css_selector(".item-2O1-TdRo")[-1]
                    driver.execute_script("return arguments[0].scrollIntoView()",last_element)
        
        except NoSuchElementException:
            print(username," does not exist in this sripts")

        except StaleElementReferenceException:
            print(username," element not available in the dome")
                
 """
        
        
        # expire on
        if sub_expire>datetime.today():
            # no expiring checkbox
            print("well")
            time.sleep(5)
            #cbdiv = WebDriverWait(driver, 10).until(EC.visibility_of_element_located((By.CSS_SELECTOR, 'div[data-name="set-date-dialog"]')))
            #checkbox = driver.find_element_by_css_selector('overlap-manager-root > div > div > div.dialog-hxnnZcZ6.dialog-HExheUfY.dialog-Nh5Cqdeo.rounded-Nh5Cqdeo.shadowed-Nh5Cqdeo > div > div.container-dv1LvhyQ > label.checkbox-dv1LvhyQ.checkbox-GxG6nBa7 > span.wrapper-5Xd5conM > input')
            #cbwrap = cbdiv.find_element_by_class('wrapper-5Xd5conM')
            #checkbox_label = checkbox.find_element_by_xpath('..')
            
            
            # format => yyyy-mm-dd
            tv_select_date(driver,wait,sub_expire)
            messages.info(request,username + "added to tv indis successfully. Expires = " + str(sub_expire)) 
        else:
            # no expire
            checkbox = driver.find_element_by_css_selector('input[type="checkbox"]')
            checkbox_label = checkbox.find_element_by_xpath('..')
            if not checkbox.get_attribute('checked'):
                checkbox_label.click()
            messages.info(request,username + "added to tv indis successfully. No expire.") 
        wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, 'button[name="submit"]'))).click()
        
def tv_remove_members(self,link:str=str(),users:List[str]=[]):
    """[summary]
    users = [
        'username1',
        'username2',
        ...
    ]
    Args:
        link (str, optional): [description]. Defaults to str().
        users (List[str], optional): [description]. Defaults to [].
    """
    if link not in self.driver.current_url:
        self.driver.get(link)

    self.driver.find_element_by_css_selector("button[data-name='manage-access']").click()

    for username in users:
        
        try:
            text = self.driver.find_element_by_css_selector(".title-30_lleAw").text
            find = re.findall(r"(\d+) users","108 users have access",re.I)
            if find:
                total = int(find[0])
                count = total/12
                
                for _ in range(int(count)):
                    sleep(0.7)
                    if username in [element.get_attribute("data-username") for element in self.driver.find_elements_by_css_selector(".item-2O1-TdRo")]:
                        self.driver.find_element_by_css_selector(f"[data-username='{username}'] span[data-name='manage-access-dialog-item-remove-button']").click()
                        break
                    last_element = self.driver.find_elements_by_css_selector(".item-2O1-TdRo")[-1]
                    self.driver.execute_script("return arguments[0].scrollIntoView()",last_element)
            
            
        except NoSuchElementException:
            print(username," does not exist in this sripts")

        except StaleElementReferenceException:
            print(username," element not available in the dom")
        
    self.driver.find_element_by_css_selector("[data-name='close']").click()

def tv_get_all_charts(driver):
        link = "https://www.tradingview.com/u/MoneyMovesInvestments/#published-scripts"
        if link not in driver.current_url:
            driver.get(link)
        data = list()
        sleep(0.2)
        for _ in range(len(driver.find_elements_by_css_selector(".js-feed__item--inited"))):
            driver.execute_script("window.scrollTo(0,document.body.scrollHeight)")
            sleep(0.2)
            driver.execute_script("window.scrollTo(0,0);")
            sleep(0.2)

        print("chart loop starts")
        for x in driver.find_elements_by_css_selector(".js-feed__item--inited"):
            link_element = x.find_element_by_css_selector("a")
            if not link_element.text and not link_element.get_attribute("href"):continue
            try:
                print(link_element.text)
                data.append({
                    "link":link_element.get_attribute("href"),
                    "name":link_element.text,
                    "data-card":json.loads(x.get_attribute("data-card") or "{}"),
                    "data-widget-data":json.loads(x.get_attribute("data-widget-data") or "{}"),
                    "id":x.id
                })
            except:
                print("element ",x.id," has no data")
                

        return data

def tv_get_chart_link_from_name(driver, name):
    try:
        gen = filter(lambda x:x.get("name") == name,tv_get_all_charts(driver=driver))
        return gen.__next__()
    except StopIteration:
        return None








def MT5Licence(request):
    current_user = request.user
    current_user_mt5 = request.user.mt5_acct
    u_id = current_user.id
    if len(current_user_mt5) != 0:
        mt5_acct = (int(request.user.mt5_acct)*2+155050)
        print(mt5_acct)
        User.objects.filter(pk=u_id).update(mt5_bk=mt5_acct)
        messages.info(request, "MT5 Licensing Terminated: EA Password -> " + str(mt5_acct))
    else:
        messages.info(request, "MT5 Licensing Failed: Set Up MT5 Account first.")
    return(redirect('home:profile'))

def ProfileCancelSub(request):

    if request.method == "POST":
        user_sub = get_user_subscription(request)

        if user_sub.sub_active is False:
            messages.info(request, "You dont have an active membership")
            return HttpResponseRedirect(request.META.get('HTTP_REFERER'))

        sub = stripe.Subscription.retrieve(user_sub.stripe_subscription_id)
        sub.delete()

        user_sub.sub_active = False
        user_sub.save()

        free_membership = Membership.objects.get(m_type='Free')
        user_membership = get_user_membership(request)
        user_membership.membership = free_membership
        user_membership.save()

        send_cancel_email(request.user, request)

        messages.info(
            request, "Successfully cancelled membership. We have sent an email.")
        # sending an email here

        return redirect(reverse('home:profile'))
    
    return(render(request,'home/profile_cancelsub.html'))

def send_cancel_email(user, request):
    current_site = get_current_site(request)
    email_subject = 'Activate your account'
    email_body = render_to_string('home/auth_f/cancel.html', {
        'user': user,
        'domain': current_site,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': generate_token.make_token(user)
    })

    email = EmailMessage(subject=email_subject, body=email_body,
                         from_email=settings.EMAIL_FROM_USER,
                         to=[user.email]
                         )

    if not settings.TESTING:
        EmailThread(email).start()