"""
URL configuration for backend_master project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    # 业务接口入口（v1）：所有系统管理与认证相关的接口都在此下方
    path('api/v1/', include('api_v1.urls')),
    # 兼容旧的直接访问路径：将部分根路径请求重定向到 api/v1 下的相应接口
    path('crawler/logs', RedirectView.as_view(url='/api/v1/crawler/logs', permanent=False)),
]

# 媒体文件服务（开发环境）
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
