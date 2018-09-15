from django.shortcuts import render
from django.http import HttpResponse,HttpResponseRedirect
from .models import User
from django.core.exceptions import ObjectDoesNotExist
import hmac
import hashlib
import os

# Create your views here.

context = {
    'Login': False,
    'SuperUser': False,
}

def index(request):
    if 'user' in request.COOKIES:
        try:
            user = User.objects.get(name=request.COOKIES['user'])
        except ObjectDoesNotExist:
            print('user in cookie does not exist? strange')
            context['Login'] = False
            context['SuperUser'] = False
            return render(request,'Home/index.html',context)
        if(str(user.cookie) == request.COOKIES['cookie']):
            context['Login'] = True
            context['name'] = user.name
            context['SuperUser'] = False
            if user.admin:
                context['SuperUser'] = True
        else:
            context['Login'] = False
    else:
        context['Login'] = False
    if (context['Login'] == False):
        context['SuperUser'] = False
    if 'alert' in request.COOKIES:
        request.COOKIES.pop('alert')
    else:
        if 'alertMsg' in context:
            context.pop('alertMsg')
    return render(request,'Home/index.html',context)
def login(request):
    response = HttpResponseRedirect("/Home/")
    response.set_cookie("alert",'alert')
    try:
        user = User.objects.get(name=request.POST['name'])
    except ObjectDoesNotExist:
        response.set_cookie("cookie","logfail")
        context['alertMsg'] = 'Login Failed!'
        return response
    h = hmac.new(key=user.salt,msg=str.encode(request.POST['password']),digestmod='sha256')
    password = h.hexdigest()
    if user.password == password:
        user.cookie = os.urandom(16)
        user.save()
        response.set_cookie("cookie",user.cookie)
        response.set_cookie("user",user.name)
        context['alertMsg'] = 'Login Succeed!'
    else:
        context['Login'] = False
        context['alertMsg'] = 'Login Failed!'
    return response
def addUser(request):
    response = HttpResponseRedirect("/Home/")
    response.set_cookie("alert",'alert')
    if (len(User.objects.filter(name=request.POST['name'])) != 0):
        context['alertMsg'] = 'User Exists!'
    else:
        context['alertMsg'] = 'NewUser Add Succeed!'
        user = User(name=request.POST['name'])
        user.salt = os.urandom(16)
        user.password = hmac.new(key=user.salt,msg=str.encode(request.POST['password']),digestmod='sha256').hexdigest()
        user.admin = False
        user.save()
    return response

def initAdmin(request):
    admin = User(name="WandSmith")
    hash = hashlib.sha256()
    hash.update(str.encode('WandSmith'))
    admin.salt = os.urandom(16)
    admin.password = hmac.new(key=admin.salt,msg=str.encode(hash.hexdigest()),digestmod='sha256').hexdigest()
    admin.admin = True
    admin.save()
    return HttpResponseRedirect("/Home/")


