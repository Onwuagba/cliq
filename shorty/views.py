from datetime import datetime, timedelta
import logging
import os
from typing import Any, Dict, List
import uuid

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.http import HttpResponse
from django.utils import timezone
from dotenv import load_dotenv
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import (
    MultiPartParser,
    JSONParser,
)
from rest_framework import status, filters
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.exceptions import PermissionDenied, ValidationError, NotFound

from common.permissions import IsAdmin, IsIPPermitted
from common.utilities.api_response import CustomAPIResponse
from shorty.models import Blacklist, Category, QRCode, ShortLink, UserShortLink
from shorty.serializers import CategorySerializer, ShortLinkSerializer
from shorty.utils import (
    contains_blacklisted_texts,
    get_user_ip,
    is_domain_blacklisted,
    is_ip_blacklisted,
    is_valid_image,
    is_valid_time_24h_format,
    validate_link,
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
            serializer = self.serializer_class(
                self.get_queryset(), many=True)
            if dat := serializer.data:
                message = dat
                status_code = status.HTTP_200_OK
                status_msg = "success"
            else:
                message = "No category found"
        except Exception as e:
            logger.error(f"Exception in CategoryView: {
                         str(e.args[0])}")
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
        IsIPPermitted,
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
            Q(link_shortlink__user=user) | Q(
                link_shortlink__session_id=user)
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
                query_response = self.get_paginated_response(
                    serializer.data)
                message = query_response.data
                status_code = status.HTTP_200_OK
                status_msg = "success"
            else:
                message = "No links created yet"
        except Exception as e:
            logger.error(f"Exception in ShortLinkView: {
                         str(e.args[0])}")
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
                raise Exception(
                    "Link not allowed. Please request a manual review.")

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
                "full_url": serializer.data["full_url"],
                "session_id": serializer.data["session_id"],
            }
            status_msg = "success"
            status_code = status.HTTP_201_CREATED
        except (PermissionDenied, Exception) as e:
            logger.error(f"POST Exception in ShortLinkView: {
                         str(e.args[0])}")
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
                link_dict["redirect_link"] = f"http://{
                    link_dict['redirect_link']}"

            updated_links_redirect.append(link_dict)

        return updated_links_redirect


class ShortlinkDetailView(RetrieveUpdateDestroyAPIView):
    permission_classes = (
        AllowAny,
        IsIPPermitted,
    )  # allow any cos non-registered user can also create link
    serializer_class = ShortLinkSerializer
    http_method_names = ["get", "patch", "delete"]
    parser_classes = [
        MultiPartParser,
        JSONParser,
    ]

    def get_queryset(self):
        return ShortLink.objects.filter(shortcode=self.kwargs["shortcode"])

    def get_object(self, user=None):
        """
        Retrieves a ShortLink object based on the provided shortcode and user.

        Parameters:
            user (str, optional): The user associated with the ShortLink object. Defaults to None.

        Returns:
            ShortLink: The ShortLink object with the specified shortcode and user.

        Raises:
            NotFound: If no ShortLink object with the specified shortcode and user is found.
        """
        try:
            obj = (
                ShortLink.objects.get(
                    shortcode=self.kwargs["shortcode"])
                if not user
                else ShortLink.objects.get(
                    (Q(link_shortlink__user=user) | Q(
                        link_shortlink__session_id=user)),
                    shortcode=self.kwargs["shortcode"],
                )  # for patch
            )
        except ShortLink.DoesNotExist:
            raise NotFound("Link not found")

        # Check if start_date is in the future
        # user is passed for patch and delete endpoints so we don't check for start_date
        if (
            not user
            and obj.start_date
            and obj.start_date > timezone.make_aware(datetime.now())
        ):
            raise NotFound("Link is not available yet")

        return obj

    def get(self, request, **kwargs):
        """
        get shortlink details
        """
        # no auth required cos this is the endpoint that is called when link is shared
        status_code = status.HTTP_400_BAD_REQUEST
        status_msg = "failed"

        try:
            obj = self.get_object()
            serializer = self.serializer_class(obj)
            message = serializer.data
            status_msg = "success"
            status_code = status.HTTP_200_OK
        except NotFound as ex:
            message = str(ex.args[0])
            status_code = status.HTTP_404_NOT_FOUND
        except Exception as e:
            logger.error(f"Exception in ShortlinkDetailView: {
                         str(e.args[0])}")
            message = str(e.args[0])

        return CustomAPIResponse(message, status_code, status_msg).send()

    def patch(self, request, *args, **kwargs):
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
                    "User not authenticated",
                    status.HTTP_401_UNAUTHORIZED,
                    status_msg,
                ).send()

            obj = self.get_object(user)
            serializer = self.serializer_class(
                obj, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            message = "Link updated successfully"
            status_code = status.HTTP_200_OK
            status_msg = "success"
        except NotFound as ex:
            message = str(ex.args[0])
            status_code = status.HTTP_404_NOT_FOUND
        except Exception as e:
            logger.error(f"Exception in ShortlinkDetailView: {
                         str(e.args[0])}")
            message = str(e.args[0])

        return CustomAPIResponse(message, status_code, status_msg).send()

    def delete(self, request, *args, **kwargs):
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
                    "User not authenticated",
                    status.HTTP_401_UNAUTHORIZED,
                    status_msg,
                ).send()

            obj = self.get_object(user)
            obj.is_deleted = True
            obj.save()
            message = "Link deleted successfully"
            status_code = status.HTTP_204_NO_CONTENT
            status_msg = "success"
        except NotFound as ex:
            message = str(ex.args[0])
            status_code = status.HTTP_404_NOT_FOUND
        except Exception as e:
            logger.error(f"Exception in ShortlinkDetailView: {
                         str(e.args[0])}")
            message = str(e.args[0])

        return CustomAPIResponse(message, status_code, status_msg).send()


######################
# GENERICS
######################


class BlacklistCheck(APIView):
    permission_classes = (
        AllowAny,
        IsIPPermitted,
    )
    serializer_class = ShortLinkSerializer
    http_method_names = ["get", "post"]
    """
    Check if a text/link/ip is blacklisted
    """

    def post(self, request, **kwargs):
        """Check if a text/link/ip is blacklisted.

        Payload:
            blacklist_type: The type of blacklist to check (ip/domain/text).
            entry: The text/link/ip to check.
        """
        blacklist_type = request.data.get("blacklist_type")
        entry = request.data.get("entry")

        if not blacklist_type or not entry:
            return CustomAPIResponse(
                "Missing blacklist_type or entry",
                status.HTTP_400_BAD_REQUEST,
                "failed",
            ).send()

        if blacklist_type == "ip":
            # pull the logged in user's IP address
            entry = entry or get_user_ip(request)
        elif blacklist_type == "domain":
            entry = validate_link(entry)
        elif blacklist_type == "text":
            entry = validate_link(entry)
        else:
            return CustomAPIResponse(
                "Invalid blacklist type",
                status.HTTP_400_BAD_REQUEST,
                "failed",
            ).send()

        return self._check_blacklist(blacklist_type, entry)

    def _check_blacklist(self, blacklist_type, entry):
        if blacklist_type == "ip":
            blacklist_check = is_ip_blacklisted(entry)
        elif blacklist_type == "domain":
            blacklist_check = is_domain_blacklisted(entry)
        elif blacklist_type == "text":
            blacklist_check = contains_blacklisted_texts(entry)
        else:
            return CustomAPIResponse(
                "Invalid blacklist type", status.HTTP_400_BAD_REQUEST, "failed"
            ).send()

        if blacklist_check:
            message = f"{blacklist_type} - {entry} is blacklisted"
            status_code = status.HTTP_200_OK
            status_msg = "success"
        else:
            message = f"{blacklist_type} - {entry} is not blacklisted"
            status_code = status.HTTP_404_NOT_FOUND
            status_msg = "failed"

        return CustomAPIResponse(message, status_code, status_msg).send()


class ValidateImage(APIView):
    permission_classes = (AllowAny, IsIPPermitted)
    http_method_names = ["post"]

    def post(self, request, **kwargs):
        image_file = request.FILES.get("image")

        if not image_file:
            return CustomAPIResponse(
                "Missing image file",
                status.HTTP_400_BAD_REQUEST,
                "failed",
            ).send()

        is_valid, message = is_valid_image(image_file)
        if is_valid:
            status_code = status.HTTP_200_OK
            status_msg = "success"
            message = "Valid image"
        else:
            status_code = status.HTTP_400_BAD_REQUEST
            status_msg = "failed"

        return CustomAPIResponse(message, status_code, status_msg).send()


class QRCodeView(APIView):
    # qr code is generated on the fly.
    # check notes for comparison between this and saving to DB
    permission_classes = (IsAuthenticated,)
    http_method_names = ["get", "post", "put"]

    def get(self, request, shortcode: str):
        try:
            qr_code = self.get_qr_code(request.user, shortcode)
            qr_image = qr_code.generate_qr_code()

            response = HttpResponse(content_type='image/png')
            response['Content-Disposition'] = f'attachment; filename="{
                shortcode.lower()}_qr.png"'
            response.write(qr_image)

            return response

        except (ShortLink.DoesNotExist, QRCode.DoesNotExist, UserShortLink.DoesNotExist):
            return CustomAPIResponse(
                "QR code not found",
                status.HTTP_404_NOT_FOUND,
                "failed"
            ).send()
        except Exception as e:
            logger.error('Exception retrieving QR code: %s', e)
            return CustomAPIResponse(
                "Oops! An error occurred",
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "failed"
            ).send()

    def post(self, request, shortcode):
        try:
            qr_code = self.get_qr_code(request.user, shortcode)

            # Update QR code properties if provided in the request
            self.update_qr_code(qr_code, request.data, request.FILES)
            qr_image = qr_code.generate_qr_code()

            response = HttpResponse(content_type='image/png')
            response['Content-Disposition'] = f'attachment; filename="{
                shortcode}_qr.png"'
            response.write(qr_image)

            return response

        except (ShortLink.DoesNotExist, QRCode.DoesNotExist, UserShortLink.DoesNotExist) as ef:
            logger.error('Link not found : %s', ef)
            return CustomAPIResponse(
                "Short link not found",
                status.HTTP_404_NOT_FOUND,
                "failed"
            ).send()
        except Exception as e:
            logger.error('Exception while creating QR code : %s', e)
            return CustomAPIResponse(
                str(e),
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "failed"
            ).send()

    def put(self, request, shortcode):
        try:
            qr_code = self.get_qr_code(request.user, shortcode)
            self.update_qr_code(qr_code, request.data, request.FILES)
            return CustomAPIResponse(
                "QR code updated successfully",
                status.HTTP_200_OK,
                "success"
            ).send()
        except ShortLink.DoesNotExist:
            return CustomAPIResponse(
                "Short link not found",
                status.HTTP_404_NOT_FOUND,
                "failed"
            ).send()
        except Exception as e:
            logger.error('Exception updating QR code: %s', e)
            return CustomAPIResponse(
                str(e),
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "failed"
            ).send()

    def get_qr_code(self, user, shortcode):
        logger.info(
            "get_qr_code from user: %s, shortcode: %s", user, shortcode)
        short_link = ShortLink.objects.get(shortcode=shortcode)
        UserShortLink.objects.get(
            link=short_link, user=user)
        qr_code, _ = QRCode.objects.get_or_create(link=short_link)
        return qr_code

    def update_qr_code(self, qr_code, data, files):
        qr_code.box_size = data.get('box_size', qr_code.box_size)
        qr_code.border = data.get('border', qr_code.border)
        qr_code.fill_color = data.get(
            'fill_color', qr_code.fill_color)
        qr_code.background_color = data.get(
            'background_color', qr_code.background_color)
        qr_code.qr_title = data.get('qr_title', qr_code.qr_title)

        if 'logo' in files:
            logo_file = files['logo']
            is_valid, message = is_valid_image(
                logo_file,
                valid_formats=["PNG", "JPEG", "JPG"],
                min_width=100,
                min_height=100,
                max_file_size=2 * 1024 * 1024  # 2 MB max file size for logos
            )
            if not is_valid:
                raise ValueError(message)
            qr_code.logo = logo_file

        qr_code.save()
