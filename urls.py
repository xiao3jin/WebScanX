"""webscan URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
import os

from django.conf.urls import url, include
from django.conf.urls.static import static  # 修改这里
from django.contrib import admin
from manager import views
from webscan import settings
from manager import views

urlpatterns = [
    url(r'^manager/', include('manager.urls')),
    url(r'^admin/', admin.site.urls),
]

# 确保 STATIC_URL 和 STATIC_ROOT 正确设置
# urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
