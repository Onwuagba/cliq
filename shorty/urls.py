from django.urls import path

from shorty.views import CategoryView, ShortLinkView

app_name = "shorty"

urlpatterns = [
    path("category/", CategoryView.as_view(), name="category"),
    path("shortlink/", ShortLinkView.as_view(), name="shortlink"),
]
