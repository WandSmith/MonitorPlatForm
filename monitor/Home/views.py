from django.shortcuts import render
from django.http import HttpResponse,HttpResponseRedirect,StreamingHttpResponse,HttpResponseServerError
from .models import User
from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators import gzip
import hmac
import hashlib
import os
import cv2
import time

class VideoCamera(object):
    def __init__(self):
        self.video = cv2.VideoCapture(0)
    def __del__(self):
        self.video.release()
    
    def get_frame(self):
        ret,image=self.video.read()
        ret,jpeg = cv2.imencode('.jpg',image)
        return jpeg.tobytes()

def gen(camera):
    while True:
        frame = camera.get_frame()
        yield(b'--frame\r\n'
        b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

@gzip.gzip_page
def videoStream(request):
    try:
        return StreamingHttpResponse(gen(VideoCamera()),content_type="multipart/x-mixed-replace;boundary=frame")
    except HttpResponseServerError:
        print("aborted")
# Create your views here.

context = {
    'Login': False,
    'SuperUser': False,
}

def index(request):
    response = render(request,'Home/index.html',context)
    if 'user' in request.COOKIES:
        try:
            user = User.objects.get(name=request.COOKIES['user'])
        except ObjectDoesNotExist:
            print('user in cookie does not exist? strange')
            context['Login'] = False
            context['SuperUser'] = False
            return response
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
    if 'alertMsg' in context:
        context.pop('alertMsg')
    return response
def login(request):
    response = HttpResponseRedirect("/Home/")
    response.set_cookie("alert",'alert')
    response.set_cookie("cookie",'')
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
        context['user'] = user.name
        context['Login'] = True
        if user.admin:
            context['SuperUser'] = True
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

def changePassword(request):
    response = HttpResponseRedirect("/Home/")
    response.set_cookie("alert",'alert')
    if 'user' in request.COOKIES:
        try:
            user = User.objects.get(name=request.COOKIES['user'])
        except ObjectDoesNotExist:
            print('user in cookie does not exist? strange')
            return HttpResponseRedirect("/Home/")
        if request.POST['newPw'] == request.POST['newPwCheck']:
            h = hmac.new(key=user.salt,msg=str.encode(request.POST['newPw']),digestmod='sha256')
            user.password = h.hexdigest()
            user.save()
            context['alertMsg'] = 'Change Succeed!'
        else:
            context['alertMsg'] = 'Different inputs of password!'    
    else:
        context['alertMsg'] = 'Not Login!'
    return response

def changePasswordIndex(request):
    return render(request,'Home/changePw.html')