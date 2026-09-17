from flask import Blueprint, jsonify, request

from app.extensions import db
from app.models import User
from app.security import create_token, token_required, verify_password, xss_escape

auth_bp = Blueprint("auth", __name__)
api_bp = Blueprint("api", __name__)


def _public_user(user: User) -> dict:
    """Сериализует пользователя в безопасный JSON (поля экранированы от XSS)."""
    return {
        "id": user.id,
        "username": xss_escape(user.username),
        "bio": xss_escape(user.bio),
    }


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    """POST /auth/login - аутентификация пользователя по логину и паролю."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    # Параметризованный запрос через ORM - защита от SQL-инъекций.
    user = db.session.execute(
        db.select(User).where(User.username == username)
    ).scalar_one_or_none()

    # Единый ответ при неверном логине ИЛИ пароле - защита от перебора (user enumeration).
    if user is None or not verify_password(password, user.password_hash):
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify(
        {
            "token": create_token(user.id),
            "token_type": "Bearer",
            "expires_in": 3600,
        }
    )


@api_bp.route("/api/data", methods=["GET"])
@token_required
def get_data(_current_user: User):
    """GET /api/data - список пользователей. Доступен только аутентифицированным."""
    users = db.session.execute(db.select(User)).scalars().all()
    return jsonify({"users": [_public_user(u) for u in users]})


@api_bp.route("/api/profile", methods=["GET"])
@token_required
def get_profile(current_user: User):
    """GET /api/profile - профиль текущего аутентифицированного пользователя."""
    return jsonify(_public_user(current_user))