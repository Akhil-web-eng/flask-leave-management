# tokens.py
from itsdangerous import URLSafeTimedSerializer
from flask import current_app

def generate_reset_token(user_id, expires_sec=3600):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return s.dumps({'user_id': user_id}, salt='password-reset-salt')

def verify_reset_token(token, expires_sec=3600):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token, salt='password-reset-salt', max_age=expires_sec)
        return data.get('user_id')
    except Exception:
        return None
