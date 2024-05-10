from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from main.models import (
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
    UserAccount,
    UserShortLink,
)


class DefaultAdmin(admin.ModelAdmin):
    ordering = ("-updated_at",)
    list_display = ("created_at", "updated_at")

    def get_queryset(self, request):
        if request.user.is_superuser and hasattr(self.model, "admin_objects"):
            return self.model.admin_objects.get_queryset()
        else:
            return self.model.objects.get_queryset()


@admin.register(UserAccount)
class CustomAdmin(UserAdmin):
    list_display = (
        "first_name",
        "last_name",
        "email",
        "channel",
        "is_active",
        "created_at",
        "updated_at",
    )

    list_filter = (
        "channel",
        "is_staff",
        "is_superuser",
        "is_active",
        "groups",
        "is_deleted",
    )

    ordering = ("created_at",)
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "first_name",
                    "last_name",
                    "is_active",
                    "channel",
                    "password1",
                    "password2",
                ),
            },
        ),
    )
    filter_horizontal = ()
    fieldsets = ()
    readonly_fields = ["created_at", "last_login"]

    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        is_superuser = request.user.is_superuser
        disabled_fields = set()

        if not is_superuser:
            disabled_fields |= {
                "is_staff",
                "is_active",
                "is_deleted",
                "is_superuser",
                "groups",
                "user_permissions",
            }

        for f in disabled_fields:
            if f in form.base_fields:
                form.base_fields[f].disabled = True

        return form

    def get_list_filter(self, request):
        if not request.user.is_superuser:
            return ("is_active", "groups", "is_deleted")
        return super().get_list_filter(request)

    def get_list_display(self, request):
        if request.user.is_superuser:
            return self.list_display + (
                "is_staff",
                "is_superuser",
            )
        else:
            return super().get_list_display(request)

    def get_queryset(self, request):
        qs = UserAccount.admin_objects.get_queryset()
        if not request.user.is_superuser:
            qs = qs.filter(is_superuser=False)
        return qs


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
        "link_password",
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
        "link_shortlink__is_link_discoverable",
        "link_shortlink__is_link_masked",
        "link_shortlink__is_link_protected",
    )

    readonly_fields = ("shortcode",)

    def user(self, obj):
        if hasattr(obj, "link_shortlink"):
            return obj.link_shortlink.user.email
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

    def link_password(self, obj):
        if hasattr(obj, "link_shortlink"):
            return obj.link_shortlink.link_password
        return None


class UserShortLinkAdmin(DefaultAdmin):
    list_display = (
        "user",
        "link",
        "is_link_discoverable",
        "is_link_masked",
        "is_link_protected",
        "link_password",
    ) + DefaultAdmin.list_display
    search_fields = (
        "link__original_link",
        "link__shortcode",
        "user__email",
        "user__first_name",
        "user__last_name",
    )
    list_filter = (
        "is_link_discoverable",
        "is_link_masked",
        "is_link_protected",
    )
    readonly_fields = ("link_password",)


class LinkReviewAdmin(DefaultAdmin):
    list_display = (
        "link",
        "status",
        "ip_address",
    ) + DefaultAdmin.list_display
    search_fields = ("link__original_link", "link__shortcode", "ip_address")
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
