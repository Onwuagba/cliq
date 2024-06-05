from django.contrib import admin
from main.admin import DefaultAdmin
from shorty.models import (
    Analytics,
    Blacklist,
    Category,
    LinkCard,
    LinkRedirect,
    LinkReview,
    LinkUTMParameter,
    QRCode,
    ReportLink,
    ShortLink,
    UserShortLink,
)


class CategoryAdmin(DefaultAdmin):
    list_display = ("name",) + DefaultAdmin.list_display
    search_fields = ("name",)


class BlacklistAdmin(DefaultAdmin):
    list_display = (
        "entry",
        "blacklist_type",
    ) + DefaultAdmin.list_display
    search_fields = ("entry",)
    list_filter = ("blacklist_type",)


class ShortLinkAdmin(DefaultAdmin):
    list_display = (
        "shortcode",
        "original_link",
        "user",
        "category",
        "start_date",
        "expiration_date",
        "tags",
        "ip_address",
        "is_link_discoverable",
        "is_link_masked",
        "is_link_protected",
    ) + DefaultAdmin.list_display
    search_fields = (
        "category__name",
        "original_link",
        "shortcode",
        "link_shortlink__user__email",
        "link_shortlink__user__first_name",
        "link_shortlink__user__last_name",
    )
    list_filter = (
        "start_date",
        "expiration_date",
        "is_deleted",
        "link_shortlink__is_link_discoverable",
        "link_shortlink__is_link_masked",
        "link_shortlink__is_link_protected",
    )

    readonly_fields = ("shortcode", "ip_address")

    def user(self, obj):
        if obj.link_shortlink and obj.link_shortlink.user:
            return obj.link_shortlink.user.email
        elif obj.link_shortlink and obj.link_shortlink.session_id:
            return obj.link_shortlink.session_id
        return None

    def is_link_discoverable(self, obj):
        if hasattr(obj, "link_shortlink"):
            return obj.link_shortlink.is_link_discoverable
        return None

    def is_link_masked(self, obj):
        if hasattr(obj, "link_shortlink"):
            return obj.link_shortlink.is_link_masked
        return None

    def is_link_protected(self, obj):
        if hasattr(obj, "link_shortlink"):
            return obj.link_shortlink.is_link_protected
        return None


class UserShortLinkAdmin(DefaultAdmin):
    list_display = (
        "user",
        "session_id",
        "link",
        "is_link_discoverable",
        "is_link_masked",
        "is_link_protected",
    ) + DefaultAdmin.list_display
    search_fields = (
        "link__original_link",
        "link__shortcode",
        "user__email",
        "user__first_name",
        "user__last_name",
        "session_id",
    )
    list_filter = (
        "is_link_discoverable",
        "is_link_masked",
        "is_link_protected",
    )
    readonly_fields = ("link_password", "session_id")


class LinkReviewAdmin(DefaultAdmin):
    list_display = (
        "link",
        "status",
        "reason",
    ) + DefaultAdmin.list_display
    search_fields = (
        "link__original_link",
        "link__shortcode",
        "reason",
    ) + DefaultAdmin.search_fields
    list_filter = ("status",)


class LinkCardAdmin(DefaultAdmin):
    list_display = (
        "link",
        "card_title",
        "card_description",
    ) + DefaultAdmin.list_display
    search_fields = (
        "link__original_link",
        "link__shortcode",
        "card_title",
        "card_description",
    )


class LinkRedirectAdmin(DefaultAdmin):
    list_display = (
        "link",
        "redirect_link",
        "device_type",
        "time_of_day",
        "country",
        "language",
        "redirect_rule",
    ) + DefaultAdmin.list_display
    search_fields = (
        "link__original_link",
        "link__shortcode",
        "redirect_link",
        "time_of_day",
        "country",
        "language",
    )
    list_filter = (
        "device_type",
        "redirect_rule",
    )


class LinkUTMParameterAdmin(DefaultAdmin):
    list_display = (
        "link",
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
    ) + DefaultAdmin.list_display
    search_fields = (
        "link__original_link",
        "link__shortcode",
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
    )


class ReportLinkAdmin(DefaultAdmin):
    list_display = (
        "short_link",
        "card_description",
    ) + DefaultAdmin.list_display
    search_fields = (
        "short_link",
        "card_description",
    )


class QRCodeAdmin(DefaultAdmin):
    list_display = (
        "link",
        "qr_title",
        "scan_count",
    ) + DefaultAdmin.list_display
    search_fields = (
        "link__original_link",
        "link__shortcode",
        "qr_title",
    )


class AnalyticsAdmin(DefaultAdmin):
    list_display = (
        "link",
        "ip_address",
        "os",
        "device_type",
        "click_time",
        "country",
        "city",
        "language",
        "user_agent",
        "referrer",
    ) + DefaultAdmin.list_display
    search_fields = (
        "link__original_link",
        "link__shortcode",
        "ip_address",
        "device_type",
        "click_time",
        "country",
        "city",
        "language",
        "user_agent",
        "referrer",
    )
    list_filter = ("os",)


admin.site.register(Category, CategoryAdmin)
admin.site.register(Blacklist, BlacklistAdmin)
admin.site.register(ShortLink, ShortLinkAdmin)
admin.site.register(LinkReview, LinkReviewAdmin)
admin.site.register(LinkCard, LinkCardAdmin)
admin.site.register(LinkRedirect, LinkRedirectAdmin)
admin.site.register(LinkUTMParameter, LinkUTMParameterAdmin)
admin.site.register(ReportLink, ReportLinkAdmin)
admin.site.register(QRCode, QRCodeAdmin)
admin.site.register(Analytics, AnalyticsAdmin)
admin.site.register(UserShortLink, UserShortLinkAdmin)
