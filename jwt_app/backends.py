from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
import jwt
from django.conf import settings

User = get_user_model()


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        print("I am in backends.py/JWTAuthenticate")
        header = request.headers.get('Authorization')
        if not header:
            return None
        try:
            token = header.split(' ')[1]
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')
        if payload['sub'] != 'access':
            raise AuthenticationFailed('Incorrect Token Type')
        user = User.objects.filter(id=payload['user_id']).first()
        if not user:
            raise AuthenticationFailed('No user found')
        return user, token
