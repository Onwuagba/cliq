from django.urls import path

from shorty.views import (
    BlacklistCheck,
    CategoryView,
    ShortLinkView,
    ShortlinkDetailView,
    ValidateImage,
)

app_name = "shorty"

urlpatterns = [
    path("category/", CategoryView.as_view(), name="category"),
    path("shortlink/", ShortLinkView.as_view(), name="shortlink"),
    path(
        "shortlink/<str:shortcode>/",
        ShortlinkDetailView.as_view(),
        name="shortlink_instance",
    ),
    path("blacklist/", BlacklistCheck.as_view(), name="blacklist"),
    path("validate_image/", ValidateImage.as_view(), name="validate_image"),
]
