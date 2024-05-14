from rest_framework.throttling import BaseThrottle, UserRateThrottle, AnonRateThrottle

from common.exceptions import ThrottledException


class CustomThrottle(BaseThrottle):
    def wait(self):
        """
        Override the wait method to raise ThrottledException when throttled.
        """
        if self.throttle_failure():
            raise ThrottledException()


class AnonLinkCreationThrottle(CustomThrottle, AnonRateThrottle):
    scope = "anon_link_creation"
    rate = "20/day"


class UserLinkCreationThrottle(CustomThrottle, UserRateThrottle):
    scope = "user_link_creation"
    rate = "100/day"
