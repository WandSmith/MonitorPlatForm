from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$',views.index, name='index'),
    url(r'^init/$',views.initAdmin,name='init'),
    url(r'^Video',views.videoStream,name='video'),
    url(r'^Login',views.login,name='login'),
    url(r'^AddUser',views.addUser,name='addUser'),
    url(r'^ChangePwIndex',views.changePasswordIndex, name='changePwIndex'),
    url(r'^ChangePw',views.changePassword,name='changePw'),
]