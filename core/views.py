from rest_framework.response import Response
from rest_framework import generics, status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .serializers import RegisterSerializer, LoginSerializer
from rest_framework.views import APIView
from django.contrib.auth.models import User
from .serializers import UserSerializer
from rest_framework.generics import RetrieveUpdateDestroyAPIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework import permissions
from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from core.models import UserProfile
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView


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




class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    @swagger_auto_schema(
        operation_summary="User login",
        operation_description="Authenticates a user and returns an access token on successful login.",
        request_body=LoginSerializer,
        responses={200: openapi.Response("Success", schema=LoginSerializer)}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']  # Get the authenticated user

        # Generate tokens using the CustomTokenObtainPairView logic
        refresh = RefreshToken.for_user(user)
        access = str(refresh.access_token)

         # Get the RUC from the UserProfile
        profile = UserProfile.objects.filter(user=user).first()
        ruc = profile.ruc if profile else None

        # Set the refresh token in a secure cookie
        response = Response({
            'access': access,
            'ruc': ruc,  # Include RUC in the response
        }, status=status.HTTP_200_OK)

        # Set the refresh token in an HttpOnly, Secure cookie
        response.set_cookie(
            key='refresh_token',
            value=str(refresh),
            httponly=True,
            secure=True,  # Ensure the cookie is sent over HTTPS
            samesite='Lax',
            max_age=60 * 60 * 24 * 7  # 1 week
        )

        return response


class UserListView(APIView):
    def get(self, request):
        users = User.objects.all()  # Get all registered users
        serializer = UserSerializer(users, many=True)  # Serialize the user data
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class UserRetrieveView(RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    
    
class CustomTokenObtainPairView(TokenObtainPairView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        # Here you can add additional response data if needed
        response.data['custom_message'] = 'Welcome!'

        # Set the refresh token in an HttpOnly, Secure cookie
        refresh_token = response.data['refresh']
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            httponly=True,   # Prevents JavaScript access
            samesite='Lax',  # Adjust as necessary (can also use 'Strict')
            max_age=60 * 60 * 24 * 7  # 1 week
        )

        return response
    
    
class CustomTokenRefreshView(TokenRefreshView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return Response({'detail': 'Refresh token not found.'}, status=401)

        # Pass the refresh token from the cookie to the super method
        data = {'refresh': refresh_token}
        request.data['refresh'] = refresh_token
        return super().post(request, *args, **kwargs)
    
    
    
import requests
from django.conf import settings
from django.contrib.auth.models import User
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from allauth.socialaccount.models import SocialAccount

class GoogleLoginView(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    callback_url = "http://localgost:3000"
    client_class = OAuth2Client

    
