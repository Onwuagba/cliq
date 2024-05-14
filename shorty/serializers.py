import logging
from django.contrib.auth import get_user_model

from rest_framework import serializers

from shorty.models import Category


logger = logging.getLogger("app")
UserModel = get_user_model()


class CategorySerializer(serializers.ModelSerializer):

    class Meta:
        model = Category
        fields = ("id", "name")
