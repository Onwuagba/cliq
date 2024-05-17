from django.urls import path

from shorty.views import CategoryView

app_name = "shorty"

urlpatterns = [
    path("category/", CategoryView.as_view(), name="category"),
]
