import logging
from datetime import timedelta

from django.db.models.signals import post_save
from django.contrib.sites.models import Site
from django.dispatch import receiver, Signal
from django.utils import timezone
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from main.constants import email_sender

from shorty.models import LinkReview, ShortLink
from main.models import CustomToken, UserAccount
from main.constants import email_sender
from main.tasks import send_email_confirmation_mail, send_notif_email

logger = logging.getLogger("app")
user_created = Signal()


@receiver(post_save, sender=LinkReview)
def handle_link_review_status_change(sender, instance: LinkReview, created, **kwargs):
    """
    Handle the change in status of a link review.

    Args:
        sender: The sender of the signal.
        instance: The instance of the LinkReview model that was saved.
        created: A boolean indicating whether the instance was created or not.

    Returns:
        None
    """
    if not created:
        print("Post save signal called cos link status changed")
        if str(instance.status).lower() in ["approved", "declined"] and hasattr(
            instance.link, "link_shortlink"
        ):
            # Send email to the user
            domain = Site.objects.get_current().domain
            url = f"https://{domain}/{instance.link.shortcode}"
            email_content = {
                "subject": f"Your link submission has been {instance.status}",
                "sender": email_sender,
                "recipient": instance.link.link_shortlink.user.email,
                "template": "link_review.html",
            }
            try:
                context = {
                    "username": instance.link.link_shortlink.user.first_name,
                    "original_url": instance.link.original_link,
                    "short_link": url,
                    "status": instance.status,
                    "reason": instance.reason,
                    "created_at": instance.link.created_at,
                }
                print(context)
                send_notif_email.delay(email_content, context)
            except Exception as e:
                logger.error(
                    f"Error sending status update email to {instance.link.link_shortlink.user.email}: {e}"
                )
                raise ValueError(
                    "An error occurred while sending the link review email"
                ) from e


@receiver(user_created)
def send_email_on_user_creation(
    sender, instance: UserAccount, created, request, **kwargs
):
    if created:
        email_content = {
            "subject": "Halo 👋 Please confirm your account on ShortLink",
            "sender": email_sender,
            "recipient": instance.email,
            "template": "verify-account.html",
        }
        try:
            tokenModel = CustomToken()

            token, new_obj = CustomToken.objects.get_or_create(
                user=instance,
            )

            # obj is being updated.
            # Called from regenerate email verification endpoint
            if not new_obj:
                token.created = timezone.localtime()
                token.verified_on = None
                token.expiry_date = tokenModel.create_expiry_date(token.created)
                token.save()

            uid = urlsafe_base64_encode(force_bytes(instance.pk))
            domain = get_current_site(request).domain
            confirm_url = reverse(
                "main:confirm_email", kwargs={"uid": uid, "token": token}
            )
            confirm_url = f"{request.scheme}://{domain}{confirm_url}"

            context = {"username": instance.first_name, "url": confirm_url}
            print(context)
            send_email_confirmation_mail.delay(email_content, context)
        except Exception as e:
            logger.error(f"Error sending welcome email to {instance.email}: {e}")
            raise ValueError("An error occurred while sending the welcome email") from e
