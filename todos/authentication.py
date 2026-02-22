from django.utils import timezone
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import VoiceAPIKey


class VoiceKeyAuthentication(BaseAuthentication):
    """
    Autenticazione tramite VoiceKey per endpoint /api/voice/*.
    Header: Authorization: VoiceKey <key>
    """
    keyword = 'VoiceKey'

    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if not auth_header.startswith(self.keyword + ' '):
            return None  # Non è una VoiceKey, lascia passare ad altri authenticator

        key = auth_header[len(self.keyword) + 1:].strip()
        if not key:
            raise AuthenticationFailed('API key non fornita')

        try:
            api_key = VoiceAPIKey.objects.select_related('user').get(key=key, is_active=True)
        except VoiceAPIKey.DoesNotExist:
            raise AuthenticationFailed({
                'success': False,
                'error': 'API key non valida o revocata',
                'help': 'Genera una nuova API key su https://bale231.pythonanywhere.com/api/voice/setup/'
            })

        # Aggiorna last_used_at
        api_key.last_used_at = timezone.now()
        api_key.save(update_fields=['last_used_at'])

        return (api_key.user, api_key)
