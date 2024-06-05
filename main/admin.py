from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from main.models import UserAccount


class DefaultAdmin(admin.ModelAdmin):
    ordering = ("-updated_at",)
    list_display = ("is_deleted", "created_at", "updated_at", "deleted_at")

    def get_queryset(self, request):
        if request.user.is_superuser and hasattr(self.model, "admin_objects"):
            return self.model.admin_objects.get_queryset()
        else:
            return self.model.objects.get_queryset()


@admin.register(UserAccount)
class CustomAdmin(UserAdmin):
    search_fields = ("first_name", "last_name", "email")
    list_display = (
        "first_name",
        "last_name",
        "email",
        "channel",
        "is_active",
        "is_deleted",
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

    ordering = ("-created_at",)
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
