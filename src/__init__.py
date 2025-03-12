from flask import Flask
import os
from flask_jwt_extended import JWTManager
from src.constants import http_status_codes
from src.model.database import db, User  # Ensure this import is correct
from flask_migrate import Migrate
from src.users.auth import auth
from src.users.cloud_nary import cloudnary
from dotenv import load_dotenv
from datetime import timedelta
from src.extentions.extensions import jwt, mail, cors  # Ensure this import is correct

load_dotenv()

print("This is the first print")

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    
    # Set configurations
    if test_config is None:
        app.config.from_mapping(
            SECRET_KEY=os.environ.get("SECRET_KEY"),
            SQLALCHEMY_DATABASE_URI=os.environ.get("SQLALCHEMY_DATABASE_URI"),
            SQLALCHEMY_TRACK_MODIFICATIONS=False,  # Fixed typo
            JWT_SECRET_KEY=os.environ.get("JWT_SECRET_KEY"),
            SQLALCHEMY_ENGINE_OPTIONS={
                "pool_pre_ping": True,   
                "pool_recycle": 280,   
                "pool_size": 10,        
                "max_overflow": 5,       
            }
        )
    else:
        app.config.from_mapping(test_config)
        
    # Email configuration
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))  # Default to 587 if not set
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
    app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL') == 'True'
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
    
    print("Mail settings loaded:")
    print(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
    print(f"MAIL_PORT: {app.config['MAIL_PORT']}")
    print(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
    
    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)
    cors.init_app(app, resources={r"/*": {"origins": "*"}})
    jwt.init_app(app)
    mail.init_app(app)  # Initialize Flask-Mail
    
    # JWT user lookup
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.get(identity)  # Fixed typo: Users -> User
    
    # Register Blueprints
    app.register_blueprint(auth)  
    app.register_blueprint(cloudnary)
    
    return app