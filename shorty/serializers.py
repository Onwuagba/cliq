import logging
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Q
from rest_framework import serializers
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.exceptions import ValidationError as DRFValidationError

from shorty.models import *
from shorty.utils import is_valid_time_24h_format


logger = logging.getLogger("app")
UserModel = get_user_model()


class CategorySerializer(serializers.ModelSerializer):

    class Meta:
        model = Category
        fields = ["id", "name"]


class BlacklistSerializer(serializers.ModelSerializer):

    class Meta:
        model = Blacklist
        fields = "__all__"


class UserShortLinkSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(
        max_length=50, read_only=True, source="user.email"
    )
    link_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = UserShortLink
        fields = (
            "id",
            "user",
            "user_email",
            "link",
            "is_link_discoverable",
            "is_link_masked",
            "is_link_protected",
            "link_password",
            "created_at",
            "updated_at",
        )


class LinkReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = LinkReview
        fields = "__all__"


class LinkCardSerializer(serializers.ModelSerializer):
    # link = serializers.PrimaryKeyRelatedField(queryset=ShortLink.objects.all())

    class Meta:
        model = LinkCard
        fields = [
            "card_title",
            "card_description",
            "card_thumbnail",  # "link"
        ]


class LinkRedirectSerializer(serializers.ModelSerializer):
    time_of_day = serializers.TimeField(
        format="%H:%M", input_formats=None, required=False
    )

    def validate_redirect_link(self, value):
        if value and not str(value).startswith(("http://", "https://")):
            return f"http://{value}"
        return value

    def validate_time_of_day(self, value):
        if value and not is_valid_time_24h_format(value):
            raise serializers.ValidationError(
                "Invalid time format. Should be HH:MM in 24h format"
            )
        return value

    class Meta:
        model = LinkRedirect
        fields = [
            # "link",
            "redirect_link",
            "device_type",
            "time_of_day",
            "country",
            "language",
            "redirect_rule",
        ]


class LinkUTMParameterSerializer(serializers.ModelSerializer):
    # link = serializers.PrimaryKeyRelatedField(queryset=ShortLink.objects.all())

    class Meta:
        model = LinkUTMParameter
        fields = (
            # "link",
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_term",
            "utm_content",
        )


class ReportLinkSerializer(serializers.ModelSerializer):

    class Meta:
        model = ReportLink
        fields = "__all__"


class QRCodeSerializer(serializers.ModelSerializer):

    class Meta:
        model = QRCode
        fields = "__all__"


class AnalyticsSerializer(serializers.ModelSerializer):

    class Meta:
        model = Analytics
        fields = "__all__"


class ShortLinkSerializer(serializers.ModelSerializer):
    ip_address = serializers.IPAddressField(write_only=True)
    tags = serializers.CharField(write_only=True)
    category_name = serializers.CharField(source="category.name", read_only=True)
    is_link_discoverable = serializers.BooleanField(
        default=False,
        source="link_shortlink.is_link_discoverable",
    )
    is_link_masked = serializers.BooleanField(
        default=False, source="link_shortlink.is_link_masked"
    )
    is_link_protected = serializers.BooleanField(
        default=False, source="link_shortlink.is_link_protected"
    )
    manual_review = serializers.BooleanField(default=False, write_only=True)
    link_password = serializers.CharField(
        write_only=True, source="link_shortlink.link_password", required=False
    )
    user = serializers.CharField(source="link_shortlink.user", required=False)
    link_card = LinkCardSerializer(required=False)
    link_utm = LinkUTMParameterSerializer(required=False)
    link_redirect = LinkRedirectSerializer(many=True, required=False)
    start_date = serializers.DateTimeField(
        format="%Y-%m-%d %H:%M:%S", input_formats=None, required=False
    )
    expiration_date = serializers.DateTimeField(
        format="%Y-%m-%d %H:%M:%S", input_formats=None, required=False
    )
    full_url = serializers.URLField(source="get_full_url", read_only=True)

    class Meta:
        model = ShortLink
        fields = (
            "original_link",
            "shortcode",
            "full_url",
            "category",
            "category_name",
            "start_date",
            "expiration_date",
            "tags",
            "get_tags",
            "ip_address",
            "is_link_discoverable",
            "is_link_masked",
            "is_link_protected",
            "link_password",
            "manual_review",
            "user",
            "link_card",
            "link_utm",
            "link_redirect",
        )

    def create(self, validated_data):
        # Extract nested data
        link_shortlink_data = validated_data.pop("link_shortlink", {})
        manual_review = validated_data.pop("manual_review", False)
        link_cards_data = validated_data.pop("link_card", {})
        link_utms_data = validated_data.pop("link_utm", [])
        link_redirects_data = validated_data.pop("link_redirect", [])
        category_name = self.initial_data.get(
            "category_name", None
        )  # serializer expects cat as pk which will not be available for newly created shortlinks

        try:
            with transaction.atomic():
                validated_data["shortcode"] = self._generate_unique_shortcode(
                    validated_data.get("shortcode")
                )

                if category_name:
                    validated_data["category"], _ = Category.objects.get_or_create(
                        name__iexact=category_name, defaults={"name": category_name}
                    )

                short_link = ShortLink.objects.create(**validated_data)

                if manual_review:
                    LinkReview.objects.create(link=short_link)

                if "user" in link_shortlink_data:
                    user_obj, user_key = self._get_user_instance(
                        link_shortlink_data["user"]
                    )
                    link_shortlink_data.pop(
                        "user"
                    )  # delete the record sent from the request
                    link_shortlink_data[user_key] = user_obj

                self._create_user_shortlink(short_link, link_shortlink_data)

                # Create nested instance for LinkCard, LinkUTMParameter and LinkRedirect
                self._create_nested_instances(
                    short_link, link_cards_data, link_utms_data, link_redirects_data
                )

        except DjangoValidationError as e:
            # Extract the error message from the DjangoValidationError
            error_message = e.messages[0] if e.messages else "An error occurred"
            logger.error(f"Validation error creating link: {str(e.args[0])}")
            raise DRFValidationError(error_message)

        except IntegrityError as e:
            logger.error(f"Integrity error creating link: {e}")
            if "shorty_shortlink_original_link_key" in str(e.args):
                raise serializers.ValidationError(
                    "Original link already exists. Please try again"
                ) from e
            raise DRFValidationError(
                "Database integrity error occurred while creating the link"
            )

        except Exception as e:
            logger.error(f"Error creating link: {e}")
            raise DRFValidationError("An error occurred while creating the link")

        return short_link

    def update(self, instance, validated_data):
        category_name = validated_data.pop("category_name", None)
        if category_name:
            category, _ = Category.objects.get_or_create(
                name__iexact=category_name, defaults={"name": category_name}
            )
            validated_data["category"] = category

        return super().update(instance, validated_data)

    def _generate_unique_shortcode(self, shortcode=None):
        """
        Generates a unique shortcode by repeatedly generating a random shortcode until a unique one is found.

        Args:
            shortcode (str, optional): The initial shortcode to use. If not provided, a random shortcode will be generated.

        Returns:
            str: A unique shortcode that does not already exist in the ShortLink model.
        """
        shortcode = shortcode or generate_shortcode()
        if not ShortLink.objects.filter(shortcode__iexact=shortcode).exists():
            return shortcode
        raise ValidationError("Shortcode %s already exists" % shortcode)

    def _get_user_instance(self, user_id):
        """
        Get the user instance with the specified user ID.
        This method is only called when user is logged in or a sessionID is passed

        Parameters:
            user_id (int): The ID of the user.

        Returns:
            UserModel: The user instance with the specified user ID.
        """
        try:
            return UserModel.objects.get(pk=user_id), "user"
        except UserModel.DoesNotExist:
            return (
                UserShortLink.objects.filter(session_id__iexact=user_id)
                .first()
                .session_id,
                "session_id",
            )
        except Exception:
            raise ValidationError("User not found")

    def _create_user_shortlink(self, short_link, link_shortlink_data):
        """
        Create a new UserShortLink instance with the given short_link and link_shortlink_data.

        Parameters:
            short_link (ShortLink): The short link object to associate the UserShortLink with.
            link_shortlink_data (dict): The data for creating the UserShortLink object.

        Returns:
            None
        """
        UserShortLink.objects.create(link=short_link, **link_shortlink_data)

    def _create_nested_instances(
        self, short_link, link_cards_data, link_utms_data, link_redirects_data
    ):
        """
        Creates nested instances of LinkCard, LinkUTMParameter, and LinkRedirect objects.

        Args:
            short_link (ShortLink): The short link object to associate the nested instances with.
            link_cards_data (dict): The data for creating LinkCard objects.
            link_utms_data (list): The data for creating LinkUTMParameter objects.
            link_redirects_data (list): The data for creating LinkRedirect objects.

        Returns:
            None
        """
        if link_redirects_data:
            link_redirect_serializer = LinkRedirectSerializer(
                data=link_redirects_data, many=True
            )
            link_redirect_serializer.is_valid(raise_exception=True)
            link_redirect_serializer.save(link=short_link)

        if link_utms_data:
            link_utm_serializer = LinkUTMParameterSerializer(data=link_utms_data)
            link_utm_serializer.is_valid(raise_exception=True)
            link_utm_serializer.save(link=short_link)

        if link_cards_data:
            link_card_serializer = LinkCardSerializer(data=link_cards_data)
            link_card_serializer.is_valid(raise_exception=True)
            link_card_serializer.save(link=short_link)

        # if link_cards_data:
        #     LinkCard.objects.create(link=short_link, **link_cards_data)
        # for link_utm_data in link_utms_data:
        #     LinkUTMParameter.objects.create(link=short_link, **link_utm_data)
        # for link_redirect_data in link_redirects_data:
        #     LinkRedirect.objects.create(link=short_link, **link_redirect_data)
