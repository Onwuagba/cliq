from datetime import timedelta

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

from main.models import LinkReview, ShortLink

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
        print('Post save signal called cos link status changed')
        if instance.status in ['approved', 'declined']:
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
    if not created:
        return

    # Check if there's no user associated with the link
    if not instance.user_set.exists():  
        expiration_date = timezone.now() + timedelta(days=30)

        # check if user did not specify an expiration date
        # -- OR -- the date set by user is greater than 30 days 
        if not instance.expiration_date or expiration_date < instance.expiration_date:
            instance.expiration_date = expiration_date
            instance.save()

