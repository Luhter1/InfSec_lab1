from flask_sqlalchemy import SQLAlchemy

# Вынесен в отдельный модуль, чтобы избежать кругового импорта:
# models.py и routes.py импортируют db на этапе импорта пакета app,
# когда в app/__init__.py сам объект db ещё не создан.
db = SQLAlchemy()