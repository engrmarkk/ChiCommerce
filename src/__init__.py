import os
from datetime import timedelta
from dotenv import load_dotenv
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate

from src.admin.admin import admin
from src.constants import http_status_codes
from src.extentions.extensions import jwt, mail, cors
from src.model.database import db, User
from src.users.auth import auth
from src.users.cloud_nary import cloudnary
from src.users.products import products
from src.users.ping import ping_blp

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    # Load environment variables
    load_dotenv()

    # Set default configuration
    app.config.from_mapping(
        # Security
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-key"),
        JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY", "super-secret-jwt-key"),
        # Database
        SQLALCHEMY_DATABASE_URI=os.getenv(
            "SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        # SQLALCHEMY_ECHO=True,
        SQLALCHEMY_ENGINE_OPTIONS={
            "pool_pre_ping": True,
            "pool_recycle": 280,
            "pool_size": 10,
            "max_overflow": 5,
        },
        # JWT Configuration
        JWT_ALGORITHM="HS256",
        JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=1),
        JWT_REFRESH_TOKEN_EXPIRES=timedelta(days=30),
        JWT_TOKEN_LOCATION=["headers"],
        JWT_HEADER_NAME="Authorization",
        JWT_HEADER_TYPE="Bearer",
        # Mail Configuration
        MAIL_SERVER="smtp.gmail.com",
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USE_SSL=False,
        MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
        MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
        MAIL_DEFAULT_SENDER=os.environ.get("MAIL_USERNAME"),
        MAIL_DEBUG=False,
    )

    # Override with test config if provided
    if test_config:
        app.config.from_mapping(test_config)

    # Validate production configuration
    if os.environ.get("FLASK_ENV") == "production":
        if app.config["JWT_SECRET_KEY"] == "super-secret-jwt-key":
            raise ValueError("JWT_SECRET_KEY must be set in production")
        if app.config["SECRET_KEY"] == "dev-secret-key":
            raise ValueError("SECRET_KEY must be set in production")
        if app.config["SQLALCHEMY_DATABASE_URI"] == "sqlite:///:memory:":
            raise ValueError("Database URI must be set in production")

    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)
    jwt.init_app(app)
    mail.init_app(app)
    cors.init_app(app, resources={r"/*": {"origins": "*"}})

    # Register blueprints
    app.register_blueprint(auth, url_prefix="/api/v1/auth")
    app.register_blueprint(admin, url_prefix="/api/v1/admin")
    app.register_blueprint(products, url_prefix="/api/v1/products")
    app.register_blueprint(cloudnary, url_prefix="/api/v1/cloudinary")
    app.register_blueprint(ping_blp)
    # JWT user lookup callback
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.get(identity)

    return app
