import logging

from django.contrib.auth import get_user_model
from dotenv import load_dotenv
from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework import status

from common.permissions import IsAdmin
from common.utilities.api_response import CustomAPIResponse
from shorty.models import Category
from shorty.serializers import CategorySerializer

logger = logging.getLogger("app")
UserModel = get_user_model()
load_dotenv()


class CategoryView(ListAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = CategorySerializer
    queryset = Category.objects.all()
    http_method_names = ["get", "post", "delete"]

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.request.method == "DELETE":
            return [IsAdmin()]
        return super().get_permissions()

    def get(self, request):
        status_code = status.HTTP_400_BAD_REQUEST
        status_msg = "failed"

        try:
            serializer = self.serializer_class(self.get_queryset(), many=True)
            if dat := serializer.data:
                message = dat
                status_code = status.HTTP_200_OK
                status_msg = "success"
            else:
                message = "No category found"
        except Exception as e:
            logger.error(f"Exception in CategoryView: {str(e.args[0])}")
            message = e.args[0]

        return CustomAPIResponse(message, status_code, status_msg).send()

    def post(self, request, *args, **kwargs):
        status_code = status.HTTP_400_BAD_REQUEST
        status_msg = "failed"

        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save()
                message = "Category created successfully"
                status_code = status.HTTP_201_CREATED
                status_msg = "success"
            else:
                message = serializer.errors
        except Exception as e:
            logger.error(f"Exception in CategoryView: {str(e)}")
            message = str(e)

        return CustomAPIResponse(message, status_code, status_msg).send()

    def delete(self, request, *args, **kwargs):
        status_code = status.HTTP_400_BAD_REQUEST
        status_msg = "failed"

        try:
            queryset = self.get_queryset()
            for category in queryset:
                category.is_deleted = True
                category.save()

            message = "Categories deleted successfully"
            status_code = status.HTTP_204_NO_CONTENT
            status_msg = "success"

        except Exception as e:
            logger.error(f"Exception in CategoryView: {str(e)}")
            message = str(e)

        return CustomAPIResponse(message, status_code, status_msg).send()
