from datetime import timedelta

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

from main.models import LinkReview, ShortLink, UserAccount, UserShortLink


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
        if instance.status in ["approved", "declined"]:
            # Send email to the user (instance.link.user.email)
            pass


@receiver(post_save, sender=ShortLink)
def set_expiration_for_anonymous_link(sender, instance: ShortLink, created, **kwargs):
    """
    Set expiration date for links created by anonymous users.

    Parameters:
    - sender: The sender of the post_save signal.
    - instance: The instance of the ShortLink model that was saved.
    - created: A boolean indicating whether the instance was created or not.

    Returns:
        None
    """
    print("Inside expiration signal")
    if not created:
        print("object is being updated")
        return

    # Check if there's no user associated with the link
    # cos we setting 30 days expiry for non-registered users who create links
    if not hasattr(instance, "link_shortlink"):
        expiry_in_30 = timezone.now() + timedelta(days=30)

        # check if user did not specify an expiration date
        # -- OR -- the date set by user is greater than 30 days
        if not instance.expiration_date or expiry_in_30 < instance.expiration_date:
            # instance.expiration_date = expiration_date
            # instance.save(update_fields=["expiration_date"])

            ShortLink.objects.filter(pk=instance.pk).update(expiration_date=expiry_in_30) # using this .update() cos the save method above triggers the signal again and only terminates cos of the 'if not created' check
