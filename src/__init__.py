from flask import Flask
import os
from flask_jwt_extended import JWTManager
from src.constants import http_status_codes
from src.model.database import db, User
from flask_migrate import Migrate
from src.users.auth import auth
from src.users.cloud_nary import cloudnary
from dotenv import load_dotenv
from datetime import datetime, timedelta
from src.extentions.extensions import jwt


load_dotenv()

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    
    # Set configurations
    if test_config is None:
        app.config.from_mapping(
            SECRET_KEY=os.environ.get("SECRET_KEY"),
            SQLALCHEMY_DATABASE_URI=os.environ.get("SQLALCHEMY_DATABASE_URI"),
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
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
        
    db.init_app(app)
    migrate = Migrate(app, db)
    # socketio.init_app(app, cors_allowed_origins="*")
    # cors.init_app(app, resources={r"/*": {"origins": "*"}})
    jwt.init_app(app)
    
    # mail.init_app(app)  
    
    
    # jwt look up
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return Users.query.get(identity)
    
    # Register Blueprints
    app.register_blueprint(auth)  
    # app.register_blueprint(admin)
    app.register_blueprint(cloudnary)
    
    

    return app
