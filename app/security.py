import html
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import jsonify, request

from app import db
from app.models import User

# Секрет для подписи JWT.
_SECRET_ENV = "JWT_SECRET_KEY"
_DEV_SECRET = "dev-secret-change-me-this-is-at-least-32-bytes"

# Срок жизни токена.
_TOKEN_TTL = timedelta(hours=1)


def get_secret() -> str:
    """Возвращает секрет подписи JWT (из окружения или дефолт)."""
    return os.environ.get(_SECRET_ENV, _DEV_SECRET)


def hash_password(password: str) -> str:
    """Хэширует пароль алгоритмом bcrypt (соль генерируется автоматически)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Проверяет пароль против bcrypt-хэша."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # Некорректный формат хэша - считаем невалидным.
        return False


def create_token(user_id: int) -> str:
    """Выпускает подписанный JWT для пользователя."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + _TOKEN_TTL,
    }
    return jwt.encode(payload, get_secret(), algorithm="HS256")


def token_required(func):
    """Декоратор: проверяет JWT в заголовке Authorization на защищённых маршрутах.

    В случае успеха передаёт в обработчик объект аутентифицированного User.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "Missing or malformed Authorization header"}), 401

        token = header[len("Bearer "):]
        try:
            payload = jwt.decode(token, get_secret(), algorithms=["HS256"])
            user_id = int(payload["sub"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except (jwt.InvalidTokenError, KeyError, ValueError):
            return jsonify({"error": "Invalid token"}), 401

        user = db.session.get(User, user_id)
        if user is None:
            return jsonify({"error": "User not found"}), 401

        return func(user, *args, **kwargs)

    return wrapper


def xss_escape(value) -> str | None:
    """Экранирует пользовательский текст от XSS.

    Пользовательские данные, возвращаемые в API, должны быть безопасны,
    если они потом попадают в HTML-контекст (браузер, SPA-шаблоны и т.п.).
    """
    if value is None:
        return None
    return html.escape(str(value), quote=True)