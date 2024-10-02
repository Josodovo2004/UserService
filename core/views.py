from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import generics, status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .serializers import RegisterSerializer, LoginSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from .serializers import UserSerializer
from rest_framework.generics import RetrieveUpdateDestroyAPIView


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

    @swagger_auto_schema(
        operation_summary="User registration",
        operation_description="Registers a new user with the provided data.",
        responses={201: openapi.Response("Created", schema=RegisterSerializer)}
    )
    def post(self, request, *args, **kwargs):
        """
        Registers a new user.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            "message": "User created successfully",
            "user": serializer.data
        }, status=status.HTTP_201_CREATED)


from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework import serializers

# Assuming LoginSerializer is already implemented correctly
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    @swagger_auto_schema(
    operation_summary="User login",
    operation_description="Authenticates a user and returns a token on successful login.",
    request_body=LoginSerializer,
    responses={200: openapi.Response("Success", schema=LoginSerializer)}
)
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']  # Make sure 'user' is returned
        
        # Generate tokens
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_200_OK)

class UserListView(APIView):
    def get(self, request):
        users = User.objects.all()  # Get all registered users
        serializer = UserSerializer(users, many=True)  # Serialize the user data
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class UserRetrieveView(RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer