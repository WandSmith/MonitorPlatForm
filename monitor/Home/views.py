from django.shortcuts import render
from django.http import HttpResponse,HttpResponseRedirect,StreamingHttpResponse,HttpResponseServerError
from .models import User
from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators import gzip
from imutils.video import VideoStream
import hmac
import hashlib
import os
import cv2
import time
import numpy as np
import argparse
import imutils

CLASSES = ["background", "aeroplane", "bicycle", "bird", "boat",
	"bottle", "bus", "car", "cat", "chair", "cow", "diningtable",
	"dog", "horse", "motorbike", "person", "pottedplant", "sheep",
	"sofa", "train", "tvmonitor"]
COLORS = np.random.uniform(0, 255, size=(len(CLASSES), 3))

def gen():
    # load our serialized model from disk
    print("[INFO] loading model...")
    net = cv2.dnn.readNetFromCaffe("MobileNetSSD_deploy.prototxt.txt", "MobileNetSSD_deploy.caffemodel")

    # initialize the video stream, allow the cammera sensor to warmup,
    print("[INFO] starting video stream...")
    vs = VideoStream(src=0).start()
    # vs = VideoStream(usePiCamera=True).start()
    time.sleep(2.0)
    while True:
        # grab the frame from the threaded video stream and resize it
	    # to have a maximum width of 400 pixels
        frame = vs.read()
        frame = imutils.resize(frame, width=400)

        # grab the frame dimensions and convert it to a blob
        (h, w) = frame.shape[:2]
        blob = cv2.dnn.blobFromImage(cv2.resize(frame, (300, 300)),
            0.007843, (300, 300), 127.5)

        # pass the blob through the network and obtain the detections and
        # predictions
        net.setInput(blob)
        detections = net.forward()

        # loop over the detections
        for i in np.arange(0, detections.shape[2]):
            # extract the confidence (i.e., probability) associated with
            # the prediction
            confidence = detections[0, 0, i, 2]

            # filter out weak detections by ensuring the `confidence` is
            # greater than the minimum confidence
            if confidence > 0.2:
                # extract the index of the class label from the
                # `detections`, then compute the (x, y)-coordinates of
                # the bounding box for the object
                idx = int(detections[0, 0, i, 1])
                box = detections[0, 0, i, 3:7] * np.array([w, h, w, h])
                (startX, startY, endX, endY) = box.astype("int")

                # draw the prediction on the frame
                label = "{}: {:.2f}%".format(CLASSES[idx],
                    confidence * 100)
                cv2.rectangle(frame, (startX, startY), (endX, endY),
                    COLORS[idx], 2)
                y = startY - 15 if startY - 15 > 15 else startY + 15
                cv2.putText(frame, label, (startX, y),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, COLORS[idx], 2)

        ret,jpeg = cv2.imencode('.jpg', frame)

        yield(b'--frame\r\n'
        b'Content-Type: image/jpeg\r\n\r\n' + jpeg.tobytes() + b'\r\n\r\n')
        

@gzip.gzip_page
def videoStream(request):
    try:
        return StreamingHttpResponse(gen(),content_type="multipart/x-mixed-replace;boundary=frame")
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
            context['SuperUser'] = False
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
    if (len(User.objects.filter(name='WandSmith')) != 0):
        return HttpResponseRedirect("/Home/")
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