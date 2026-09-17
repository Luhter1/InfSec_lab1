import os

from flask import Flask

from app import models
from app.extensions import db
from app.routes import api_bp, auth_bp
from app.models import User
from app.security import hash_password

# Демо-данные: логин / пароль / bio. Bio содержит потенциально опасный HTML
_DEMO_USERS = [
    ("alice", "P@ssw0rd!alice", "Just a demo user <script>alert('xss')</script>"),
    ("bob", "P@ssw0rd!bob", "Another demo user <img src=x onerror=alert(1)>"),
]


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)

    instance_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance")
    os.makedirs(instance_dir, exist_ok=True)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
        instance_dir, "app.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    if test_config:
        app.config.update(test_config)

    db.init_app(app)

    with app.app_context():
        db.create_all()
        _seed_demo_users()

    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    return app


def _seed_demo_users() -> None:
    if db.session.execute(db.select(User)).first() is not None:
        return

    for username, password, bio in _DEMO_USERS:
        db.session.add(
            User(username=username, password_hash=hash_password(password), bio=bio)
        )
    db.session.commit()