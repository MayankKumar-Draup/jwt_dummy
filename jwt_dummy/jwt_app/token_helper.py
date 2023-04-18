import jwt
from datetime import datetime, timedelta
from django.conf import settings


def generate_token(payload, exp_minutes, token_type='access'):
    exp = datetime.utcnow() + timedelta(minutes=exp_minutes)
    payload['exp'] = exp
    payload['iat'] = datetime.utcnow()
    payload['sub'] = token_type
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token
