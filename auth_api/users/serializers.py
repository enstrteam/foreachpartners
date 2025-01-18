from rest_framework import serializers
from django.utils.timezone import now, timedelta
from rest_framework_simplejwt.tokens import AccessToken
from .models import RefreshToken, CustomUser
from constance import config
import uuid

class UserRegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        from django.contrib.auth import authenticate
        user = authenticate(email=data['email'], password=data['password'])
        if not user:
            raise serializers.ValidationError("Invalid email or password.")
        return {'user': user}

    def create_tokens(self, user):
        # Generate Access Token
        access_token = str(AccessToken.for_user(user))
        # Generate Refresh Token and save to DB
        refresh_token = RefreshToken.objects.create(
            user=user,
            expires_at=now() + config.REFRESH_TOKEN_LIFETIME  # Default expiry 30 days
        )
        return {
            'access_token': access_token,
            'refresh_token': str(refresh_token.token)
        }

class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.UUIDField()

    def validate(self, data):
        try:
            refresh_token = RefreshToken.objects.get(token=data['refresh_token'])
        except RefreshToken.DoesNotExist:
            raise serializers.ValidationError("Invalid refresh token.")

        if refresh_token.expires_at < now():
            raise serializers.ValidationError("Refresh token has expired.")

        return {'refresh_token': refresh_token}

    def create_tokens(self, refresh_token):
        user = refresh_token.user
        # Generate new Access Token
        access_token = str(AccessToken.for_user(user))
        # Generate a new Refresh Token (optionally, update the existing one)
        refresh_token.token = uuid.uuid4()  # Update UUID
        refresh_token.expires_at = now() + timedelta(days=30)  # Extend expiration
        refresh_token.save()

        return {
            'access_token': access_token,
            'refresh_token': str(refresh_token.token)
        }

class MeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email'] 
        read_only_fields = ['id', 'email'] 