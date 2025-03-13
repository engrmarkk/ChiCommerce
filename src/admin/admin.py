from src.extentions.extensions import jwt, mail, cors  # Ensure this import is correct
from sqlalchemy.exc import SQLAlchemyError
from flask import Flask, request, session, url_for, redirect, Blueprint, jsonify, current_app
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import validators, re
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, current_user
import logging, os, random, string, datetime, traceback
import cloudinary
from itsdangerous import URLSafeTimedSerializer, BadSignature
import cloudinary.uploader
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from src.model.database import db, User
from src.constants import http_status_codes
from flask_mail import Message, Mail  # Import the mail instance here
from dotenv import load_dotenv
from datetime import timedelta
from urllib.parse import quote 
from urllib.parse import unquote

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Blueprint setup
admin = Blueprint("admin", __name__, url_prefix="/admin")

# Cloudinary Config
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_API_SECRET')
)

# Password validation function
def validate_password(password):
    if len(password) < 6:
        return "Password must be at least 6 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."
    return None





# Register Admin Endpoint
@admin.post("/register_admin")
def register_admin():
    # Extract request data
    username = request.json.get("username")
    first_name = request.json.get("first_name")
    last_name = request.json.get("last_name")
    email = request.json.get("email")
    password = request.json.get("password")
    phone_number = request.json.get("phone_number")
    confirm_password = request.json.get("confirm_password")

    # Validate password
    password_error = validate_password(password)
    if password_error:
        return jsonify({"message": password_error}), http_status_codes.HTTP_400_BAD_REQUEST

    if password != confirm_password:
        return jsonify({"message": "Passwords do not match"}), http_status_codes.HTTP_400_BAD_REQUEST

    # Email validation
    if not validators.email(email):
        return jsonify({"message": "Invalid email address"}), http_status_codes.HTTP_400_BAD_REQUEST

    # Check if email already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"message": "Email already in use"}), http_status_codes.HTTP_409_CONFLICT

    # Hash password
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    # Generate email verification token
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    verification_token = s.dumps(email, salt="email-verification-salt")
    logger.info(f"Generated verification token: {verification_token}")

    # Create new user
    new_user = User(
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email.lower(),
        password=hashed_password,
        phone_number=phone_number,
        verification_token=verification_token,
        is_admin=True
    )

    try:
        # Save user to database
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"New admin registered: {email}")

        # Generate verification URL with URL-encoded token
        # Send Verification Email
        verification_url = (
        f"https://chi-icon.onrender.com/admin/verify_admin/{verification_token}"
    )
        try:
            msg = Message(
                "Verify Your Email", sender=os.getenv("MAIL_USERNAME"), recipients=[email]
            )
            msg.html = f"""
            <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        background-color: #f4f4f4;
                        margin: 0;
                        padding: 20px;
                        display: flex; /* Use flexbox on body */
                        justify-content: center; /* Center content horizontally */
                        align-items: center; /* Center content vertically */
                        height: 100vh; /* Full viewport height */
                    }}
                    .container {{
                        background-color: #ffffff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                        max-width: 600px;
                        width: 100%; /* Ensure it doesn't exceed the viewport */
                        text-align: center;  /* Center text */
                    }}
                    img {{
                        width: 250px;
                        height: auto;
                        display: block;
                        margin: auto
                    }}
                    h2 {{
                        color: gray;
                    }}
                    p {{
                        font-size: 18px;
                    }}
                    .button {{
                        display: inline-block;
                        background-color: #4CAF50;
                        color: white;
                        padding: 10px 20px;
                        border: none;
                        border-radius: 5px;
                        text-decoration: none;
                        font-size: 16px;
                        margin: 20px auto;
                        cursor: pointer;
                        padding: 10px 20px;
                        transition: background-color 0.3s;
                    }}
                    .button:hover {{
                        background-color: #45a049;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <img src="https://res.cloudinary.com/de8pdqpun/image/upload/v1737536089/logo_new_upsyih.svg" alt="Company Logo">
                    <h2>You are almost there, {first_name} {last_name},</h2>
                    <p>Please verify your email by clicking the link below:</p>
                    <a href="{verification_url}" class="button">Verify Email</a>
                    <p>Thank you!</p>
                </div>
            </body>
        </html>
        """

            mail.send(msg)
            logger.info("Verification email sent successfully")
            return jsonify({"message": "User registered successfully. Please verify your email.", "user": user.to_dict()}), http_status_codes.HTTP_201_CREATED

        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            return (
                jsonify({"message": f"Error sending email: {str(e)}"}),
                http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    except Exception as e:
        logger.error(f"Error during registration: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"message": "Error registering user"}), http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR
    


    
    
    
    

# Send Email Verification
@admin.get("/verify_admin/<string:token>")
def verify_email(token):
    """Verify email using the token."""
    try:
        
        mail = current_app.extensions.get('mail')
        if not mail:
            raise RuntimeError("Flask-Mail not initialized")
        
        s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        print(f"Received token: {token}")  # Debug
        
        # Decode the token from the URL if necessary
        token = unquote(token)  # URL decode the token if it was URL-encoded
        
        email = s.loads(token, salt="email-verification-salt", max_age=3600)  # 24 hours
        
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"message": "User not found."}), 404
        
        if user.email_verified:
            return redirect("https://servicenest.netlify.app/login")
        
        # Validate the token against the database
        print(f"Stored token: {user.verification_token}")  # Debug
        print(f"Received token: {token}")  # Debug
        
        if user.verification_token != token:
            print("Invalid or expired token.")
            return (
                jsonify({"message": "Invalid or expired token."}),
                http_status_codes.HTTP_400_BAD_REQUEST,
            )
        
        print(f"User {user.email} verification status: {user.email_verified}")
        
        user.email_verified = True
        user.verification_token = None
        db.session.commit()

        return jsonify({"message": "Email verified successfully."}), http_status_codes.HTTP_200_OK

    except Exception as e:
        return jsonify({"message": f"Token verification failed: {str(e)}"}), http_status_codes.HTTP_400_BAD_REQUEST








# Resend Email Verification
@admin.post("/resend-verification_admin")
def resend_verification():
    email = request.json.get("email")
    user = Users.query.filter_by(email=email).first()

    if not user:
        return jsonify({"message": "User not found."}), http_status_codes.HTTP_404_NOT_FOUND

    if user.email_verified:
        return jsonify({"message": "Email is already verified."}), http_status_codes.HTTP_400_BAD_REQUEST

    # Generate a new token
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    new_token = s.dumps(user.email, salt="email-verification-salt")

    user.verification_token = new_token
    db.session.commit()

    verification_url = f"http://your-domain.com/verify/{new_token}"
    try:
        msg = Message("Verify Your Email", 
                    sender=os.getenv('MAIL_USERNAME'), 
                    recipients=[email])
        msg.body = f"Hi {user.first_name},\n\nPlease verify your email by clicking the link below:\n{verification_url}\n\nThank you!"
        mail.send(msg)  # Use the mail instance directly
    except Exception as e:
        return jsonify({"message": f"Error sending email: {str(e)}"}), http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR

    return jsonify({"message": "Verification email resent."}), http_status_codes.HTTP_200_OK






# Admin login
@admin.post("/login_admin")
def login():
    email = request.json.get("email", "")
    password = request.json.get("password", "")

    user = Users.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({"message": "Invalid email or password"}), http_status_codes.HTTP_401_UNAUTHORIZED

    access_token = create_access_token(identity=user.id, fresh=True)
    refresh_token = create_refresh_token(identity=user.id)

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {   
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,            
            "email": user.email,
            "profile_pic": user.profile_pic,
            "is_admin": user.is_admin
        }
    }), http_status_codes.HTTP_200_OK
    
    