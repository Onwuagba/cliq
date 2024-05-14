"""
URL configuration for shortlink project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
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
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

openapi_info = openapi.Info(
    title="ShortLink API",
    default_version="v1",
    description="The URL Shortening API allows clients to generate short, customized URLs from long URLs. These short URLs are easier to share and manage, making them ideal for various applications such as social media, marketing campaigns, and analytics tracking.",
    terms_of_service="https://www.shortlink.com/policies/terms/",
    contact=openapi.Contact(email="contact@shortlink.com"),
    license=openapi.License(name="BSD License"),
)

schema_view = get_schema_view(
    openapi_info,
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path(
        "swagger<format>/", schema_view.without_ui(cache_timeout=0), name="schema-json"
    ),  # swagger.josn or swagger.yaml
    path(
        "api/vi/doc/",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="shortlink_doc",
    ),
    path("redoc/", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"),
    path("admin/", admin.site.urls),
    path("api/vi/auth/", include("main.urls")),
]
