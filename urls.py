from django.conf.urls.defaults import *
from django.contrib.auth.views import login, logout
from django.conf import settings
from django.conf.urls.defaults import *
from newapp.views import *

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    # Example:
    # (r'^pw_server/', include('pw_server.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # (r'^admin/', include(admin.site.urls)),
	(r'^accounts/login/$',  login),
	(r'^accounts/logout/$', logout),
)
