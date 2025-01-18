from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.utils.timezone import now
from .models import CustomUser, RefreshToken  
from .serializers import UserRegistrationSerializer,LoginSerializer, RefreshTokenSerializer, MeSerializer

class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            if CustomUser.objects.filter(email=serializer.validated_data['email']).exists():
                return Response({'email': ['user with this email already exists.']}, status=status.HTTP_400_BAD_REQUEST)

            user = CustomUser.objects.create_user(
                email=serializer.validated_data['email'],  
                password=serializer.validated_data['password']
            )
            return Response({'id': user.id, 'email': user.email}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            tokens = serializer.create_tokens(user)
            return Response(tokens, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RefreshTokenView(APIView):
    def post(self, request):
        serializer = RefreshTokenSerializer(data=request.data)
        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh_token']
            tokens = serializer.create_tokens(refresh_token)
            return Response(tokens, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    def post(self, request):
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken.objects.get(token=refresh_token)
        except RefreshToken.DoesNotExist:
            return Response({"error": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST)

        if token.expires_at < now():
            return Response({"error": "Refresh token has expired."}, status=status.HTTP_400_BAD_REQUEST)

        # Mark the token as inactive or delete it
        token.delete()

        return Response({"success": "User logged out."}, status=status.HTTP_200_OK)

class MeView(APIView):
    permission_classes = [IsAuthenticated]  

    def get(self, request):
        serializer = MeSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        serializer = MeSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)