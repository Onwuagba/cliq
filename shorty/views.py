import logging
import uuid

from django.contrib.auth import get_user_model
from django.db.models import Q
from dotenv import load_dotenv
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status, filters
from django_filters.rest_framework import DjangoFilterBackend

from common.permissions import IsAdmin
from common.utilities.api_response import CustomAPIResponse
from shorty.models import Category, ShortLink, UserShortLink
from shorty.serializers import CategorySerializer, ShortLinkSerializer

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
        endpoint to get links created by user (token or via param)
        For param: ?session_id=<user_id>

        Return the list of ShortLink objects created by the user
        If the user is authenticated, the endpoint will return links
        created by the user. If the user is not authenticated,
        the endpoint will check for session_id parameter in the
        request query parameters. If session_id is provided, the
        endpoint will return links created by the user specified
        by the session_id.

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
                else request.query_params.get("session_id")
            )

            if not user:
                return CustomAPIResponse(
                    "unauthorised access", status_code, status_msg
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
