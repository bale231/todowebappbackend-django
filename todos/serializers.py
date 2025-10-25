# todos/serializers.py
from datetime import timedelta
from django.contrib.auth import get_user_model, authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import FriendRequest, Friendship, Profile

class EmailOrUsernameTokenObtainPairSerializer(TokenObtainPairSerializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Aggiungi il campo remember_me
        self.fields['remember_me'] = serializers.BooleanField(default=False, required=False)

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        return token

    def validate(self, attrs):
        remember_me = attrs.pop('remember_me', False)
        identifier = (attrs.get(self.username_field) or "").strip()
        password = attrs.get("password") or ""

        candidates = []
        if "@" in identifier:
            candidates = list(User.objects.filter(email__iexact=identifier))
            if not candidates:
                u = User.objects.filter(username__iexact=identifier).first()
                if u: candidates = [u]
        else:
            u = User.objects.filter(username__iexact=identifier).first()
            if u:
                candidates = [u]
            else:
                candidates = list(User.objects.filter(email__iexact=identifier))

        for u in candidates:
            if authenticate(username=u.username, password=password):
                attrs[self.username_field] = u.username
                break

        data = super().validate(attrs)

        # Se remember_me è True, crea token con durata estesa
        if remember_me:
            refresh = RefreshToken.for_user(self.user)
            # Token che dura 30 giorni se "rimani connesso"
            refresh.set_exp(lifetime=timedelta(days=30))
            refresh.access_token.set_exp(lifetime=timedelta(days=7))  # Access token 7 giorni

            data['refresh'] = str(refresh)
            data['access'] = str(refresh.access_token)

        return data


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer per il profilo utente pubblico"""
    full_name = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'username', 'full_name', 'profile_picture']

    def get_full_name(self, obj):
        profile = getattr(obj, 'profile', None)
        if profile:
            return profile.get_full_name()
        return obj.username

    def get_profile_picture(self, obj):
        profile = getattr(obj, 'profile', None)
        if profile and profile.profile_picture:
            return profile.profile_picture.url
        return None


class FriendRequestSerializer(serializers.ModelSerializer):
    from_user = UserProfileSerializer(read_only=True)
    to_user = UserProfileSerializer(read_only=True)

    class Meta:
        model = FriendRequest
        fields = ['id', 'from_user', 'to_user', 'status', 'created_at']


class FriendshipSerializer(serializers.ModelSerializer):
    friend = serializers.SerializerMethodField()

    class Meta:
        model = Friendship
        fields = ['id', 'friend', 'created_at']

    def get_friend(self, obj):
        request_user = self.context.get('request_user')
        friend = obj.user2 if obj.user1 == request_user else obj.user1
        return UserProfileSerializer(friend).data