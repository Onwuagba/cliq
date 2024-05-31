from datetime import timedelta
import logging
import os
from typing import Any, Dict, List
import uuid

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone
from dotenv import load_dotenv
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import (
    MultiPartParser,
    JSONParser,
)
from rest_framework import status, filters
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.exceptions import PermissionDenied, ValidationError

from common.permissions import IsAdmin
from common.utilities.api_response import CustomAPIResponse
from shorty.models import Category, ShortLink, UserShortLink
from shorty.serializers import CategorySerializer, ShortLinkSerializer
from shorty.utils import (
    contains_blacklisted_texts,
    get_user_ip,
    is_domain_blacklisted,
    is_ip_blacklisted,
    is_valid_image,
    is_valid_time_24h_format,
)

logger = logging.getLogger("app")
UserModel = get_user_model()
load_dotenv()


class CategoryView(ListAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = CategorySerializer
    queryset = Category.objects.all()
    http_method_names = ["get", "post", "delete"]

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.request.method == "DELETE":
            return [IsAdmin()]
        return super().get_permissions()

    def get(self, request):
        status_code = status.HTTP_400_BAD_REQUEST
        status_msg = "failed"

        try:
            serializer = self.serializer_class(self.get_queryset(), many=True)
            if dat := serializer.data:
                message = dat
                status_code = status.HTTP_200_OK
                status_msg = "success"
            else:
                message = "No category found"
        except Exception as e:
            logger.error(f"Exception in CategoryView: {str(e.args[0])}")
            message = e.args[0]

        return CustomAPIResponse(message, status_code, status_msg).send()

    def post(self, request, *args, **kwargs):
        status_code = status.HTTP_400_BAD_REQUEST
        status_msg = "failed"

        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save()
                message = "Category created successfully"
                status_code = status.HTTP_201_CREATED
                status_msg = "success"
            else:
                message = serializer.errors
        except Exception as e:
            logger.error(f"Exception in CategoryView: {str(e)}")
            message = str(e)

        return CustomAPIResponse(message, status_code, status_msg).send()

    def delete(self, request, *args, **kwargs):
        status_code = status.HTTP_400_BAD_REQUEST
        status_msg = "failed"

        try:
            queryset = self.get_queryset()
            for category in queryset:
                category.is_deleted = True
                category.save()

            message = "Categories deleted successfully"
            status_code = status.HTTP_204_NO_CONTENT
            status_msg = "success"

        except Exception as e:
            logger.error(f"Exception in CategoryView: {str(e)}")
            message = str(e)

        return CustomAPIResponse(message, status_code, status_msg).send()


class ShortLinkView(ListAPIView):
    permission_classes = (
        AllowAny,
    )  # allow any cos non-registered user can also create link
    serializer_class = ShortLinkSerializer
    http_method_names = ["get", "post"]
    parser_classes = [
        MultiPartParser,
        JSONParser,
    ]
    filter_backends = (DjangoFilterBackend, filters.SearchFilter)
    filterset_fields = [
        "start_date",
        "expiration_date",
        "link_shortlink__is_link_discoverable",
        "link_shortlink__is_link_masked",
        "link_shortlink__is_link_protected",
    ]
    search_fields = [
        "original_link",
        "shortcode",
        "tags",
        "ip_address",
        "category__name",
        "link_shortlink__user__email",
        "link_shortlink__user__first_name",
        "link_shortlink__user__last_name",
        "get_tags",
    ]

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.request.method == "DELETE":
            return [IsAdmin()]
        return super().get_permissions()

    def get_queryset(self, user: UserShortLink):
        return ShortLink.custom_objects.filter(
            Q(link_shortlink__user=user) | Q(link_shortlink__session_id=user)
        )

    def get(self, request):
        """
        endpoint to get links created by user (auth_token or via header)
        For param: ShortID=<id_created_for_anonymous_user>

        Return the list of ShortLink objects created by the user
        If the user is authenticated, the endpoint will return links
        created by the user. If the user is not authenticated,
        the endpoint will check for ShortID header in the
        request. If ShortID is provided, the
        endpoint will return links created by the user specified
        by the ShortID.

        :return: CustomAPIResponse object containing the list of
                    ShortLink objects or an error message if
                    something went wrong.
        """
        status_code = status.HTTP_400_BAD_REQUEST
        status_msg = "failed"

        try:
            user = (
                request.user.id
                if request.user.is_authenticated
                else request.META.get("HTTP_SHORTID")
            )

            if not user:
                return CustomAPIResponse(
                    "No shortened links found for you",
                    status_code,
                    status_msg,
                ).send()

            queryset = self.filter_queryset(self.get_queryset(user))

            if page := self.paginate_queryset(queryset):
                serializer = self.serializer_class(page, many=True)
                query_response = self.get_paginated_response(serializer.data)
                message = query_response.data
                status_code = status.HTTP_200_OK
                status_msg = "success"
            else:
                message = "No links created yet"
        except Exception as e:
            logger.error(f"Exception in ShortLinkView: {str(e.args[0])}")
            message = str(e.args[0])

        return CustomAPIResponse(message, status_code, status_msg).send()

    def post(self, request, **kwargs):
        """
        create new shortlink
        """
        status_code = status.HTTP_400_BAD_REQUEST
        status_msg = "failed"

        try:
            data = request.data.copy()
            user_ip = get_user_ip(request)

            if "original_link" not in data:
                raise Exception("original_link is required")

            original_link = data["original_link"]

            if not original_link.startswith(("http://", "https://")):
                data["original_link"] = "http://" + original_link

            # validate redirect urls
            if data.get("link_redirect"):
                data["link_redirect"] = self._validate_redirect_urls(
                    data["link_redirect"]
                )

            # validate card thumbnail
            card = data.get("link_card", {})
            if card and card.get("card_thumbnail"):
                stat, msg = is_valid_image(card.get("card_thumbnail"))
                if not stat:
                    raise ValidationError(msg)

            if is_domain_blacklisted(original_link) or contains_blacklisted_texts(
                original_link
            ):
                raise Exception("Link not allowed. Please request a manual review.")

            if is_ip_blacklisted(user_ip):
                raise PermissionDenied("Request not permitted")

            data["ip_address"] = user_ip

            user = (
                request.user.id
                if request.user.is_authenticated
                else request.META.get("HTTP_SHORTID")
            )

            if user:
                data["user"] = str(user)
            else:
                # user is not authenticated so set expiration time for link
                data["expiration_date"] = timezone.now() + timedelta(
                    days=int(os.getenv("DEFAULT_EXPIRATION_DAYS"))
                )

            serializer = self.serializer_class(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            message = {
                "shortcode": serializer.data["shortcode"],
                "original_link": serializer.data["original_link"],
                "full_url": "TRUE",
            }
            status_msg = "success"
            status_code = status.HTTP_201_CREATED
        except (PermissionDenied, Exception) as e:
            logger.error(f"POST Exception in ShortLinkView: {str(e.args[0])}")
            message = str(e.args[0])
            status_code = (
                status.HTTP_403_FORBIDDEN
                if isinstance(e, PermissionDenied)
                else status_code
            )

        return CustomAPIResponse(message, status_code, status_msg).send()

    def _validate_redirect_urls(
        self, links_redirect: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Validate and update urls in redirect links to ensure they start with http:// or https://

        Args:
            links_redirect (list): List of link dictionaries

        Returns:
            list: List of link dictionaries with urls updated
        """

        updated_links_redirect = []
        for link_dict in links_redirect:
            if "time_of_day" in link_dict and not is_valid_time_24h_format(
                link_dict["time_of_day"]
            ):
                raise ValidationError(
                    "Invalid time format. Should be HH:MM in 24h format"
                )

            if "redirect_link" in link_dict and not link_dict[
                "redirect_link"
            ].startswith(("http://", "https://")):
                link_dict["redirect_link"] = f"http://{link_dict['redirect_link']}"

            updated_links_redirect.append(link_dict)

        return updated_links_redirect
