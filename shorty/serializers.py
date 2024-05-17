import logging
from django.contrib.auth import get_user_model

from rest_framework import serializers

from shorty.models import *


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

    class Meta:
        model = LinkCard
        fields = "__all__"


class LinkRedirectSerializer(serializers.ModelSerializer):

    class Meta:
        model = LinkRedirect
        fields = "__all__"


class LinkUTMParameterSerializer(serializers.ModelSerializer):

    class Meta:
        model = LinkUTMParameter
        fields = "__all__"


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
    is_link_discoverable = serializers.BooleanField(
        default=False,
        source="link_shortlink.is_link_discoverable",
    )
    is_link_masked = serializers.BooleanField(
        default=False, source="link_shortlink.is_link_discoverable"
    )
    is_link_protected = serializers.BooleanField(
        default=False, source="link_shortlink.is_link_discoverable"
    )
    link_password = serializers.CharField(
        write_only=True, source="link_shortlink.link_password", required=False
    )
    link_card = serializers.ListField(child=LinkCardSerializer(), required=False)
    link_utm = LinkUTMParameterSerializer(many=True)
    link_redirect = LinkRedirectSerializer(many=True)

    class Meta:
        model = ShortLink
        fields = (
            "original_link",
            "shortcode",
            "category",
            "start_date",
            "expiration_date",
            "get_tags",
            "ip_address",
            "is_link_discoverable",
            "is_link_masked",
            "is_link_protected",
            "link_password",
            "link_card",
            "link_utm",
            "link_redirect",
        )


# class ShortLinkSerializer(serializers.ModelSerializer):
#     user_shortlink = UserShortLinkSerializer()
#     link_card = serializers.ListField(child=LinkCardSerializer(), required=False)

#     class Meta:
#         model = ShortLink
#         fields = (
#             "original_link",
#             "shortcode",
#             "category",
#             "start_date",
#             "expiration_date",
#             "get_tags",
#             "ip_address",
#             "user_shortlink",
#             "link_card",
#         )

#     def to_representation(self, instance):
#         representation = super().to_representation(instance)

#         if hasattr(instance, "link_shortlink") and instance.link_shortlink:
#             user_shortlink = instance.link_shortlink
#             representation["user_shortlink"] = {
#                 "id": user_shortlink.id,
#                 "user_id": user_shortlink.user.id,
#                 "is_link_discoverable": user_shortlink.is_link_discoverable,
#                 "is_link_masked": user_shortlink.is_link_masked,
#                 "is_link_protected": user_shortlink.is_link_protected,
#                 "link_password": user_shortlink.link_password,
#             }
#         else:
#             representation["user_shortlink"] = {}

#         return representation
