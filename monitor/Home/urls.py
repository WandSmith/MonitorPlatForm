from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$|^Home/$',views.index, name='index'),
    #url(r'^init/$',views.initAdmin,name='init'),
    url(r'^Login',views.login,name='login'),
    url(r'^AddUser',views.addUser,name='addUser'),
]