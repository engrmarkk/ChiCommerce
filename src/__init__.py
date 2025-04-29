from flask import Flask
import os
from flask_jwt_extended import JWTManager
from src.constants import http_status_codes
from flask_login import LoginManager
from src.model.database import db, User
from flask_migrate import Migrate
from src.users.auth import auth
from src.admin.admin import admin
from src.users.cloud_nary import cloudnary
from dotenv import load_dotenv
from datetime import timedelta
from src.extentions.extensions import jwt, mail, cors

load_dotenv()

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    
    # Set configurations
    if test_config is None:
        app.config.from_mapping(
            SECRET_KEY=os.environ.get("SECRET_KEY"),
            SQLALCHEMY_DATABASE_URI=os.getenv("SQLALCHEMY_DATABASE_URI"),    
            SQLALCHEMY_ECHO=True,           
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY"),
            
            # JWT Configuration
            JWT_ALGORITHM='HS256',  # Explicitly set the algorithm
            JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=1),
            JWT_REFRESH_TOKEN_EXPIRES=timedelta(days=30),
            JWT_TOKEN_LOCATION=['headers'],
            JWT_HEADER_NAME='Authorization',
            JWT_HEADER_TYPE='Bearer',
            
            # Mail Configuration
            MAIL_SERVER='smtp.gmail.com',
            MAIL_PORT=587,
            MAIL_USE_TLS=True,
            MAIL_USE_SSL=False,
            MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
            MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
            MAIL_DEFAULT_SENDER=os.environ.get("MAIL_USERNAME"),
            MAIL_DEBUG=True,
            MAIL_SUPPRESS_SEND=False,
            
            # Database Pool Configuration
            SQLALCHEMY_ENGINE_OPTIONS={
                "pool_pre_ping": True,
                "pool_recycle": 280,
                "pool_size": 10,
                "max_overflow": 5,
            }
        )
    else:
        app.config.from_mapping(test_config)
    
    # Validate JWT_SECRET_KEY is set
    if not app.config['JWT_SECRET_KEY']:
        raise ValueError("JWT_SECRET_KEY is not set in configuration")
    
    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)
    jwt.init_app(app)
    mail.init_app(app)
    cors.init_app(app, resources={r"/*": {"origins": "*"}})
    
    # Debug prints (remove in production)
    print("\nConfiguration Check:")
    print(f"JWT_SECRET_KEY set: {'Yes' if app.config['JWT_SECRET_KEY'] else 'No'}")
    print(f"JWT_ALGORITHM: {app.config['JWT_ALGORITHM']}")
    print(f"MAIL_USERNAME: {app.config.get('MAIL_USERNAME')}\n")
    
    # Register Blueprints
    app.register_blueprint(auth)
    app.register_blueprint(admin)
    app.register_blueprint(cloudnary)
    
    # JWT user lookup callback
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.get(identity)
    
    return app