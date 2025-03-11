from flask import Flask, request, session, url_for, redirect, Blueprint, jsonify, current_app
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import validators, re
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, current_user
import logging, os, random, string, datetime, traceback
import cloudinary
import cloudinary.uploader
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from sqlalchemy.exc import IntegrityError
from src.model.database import db, User
from src.constants import http_status_codes
from flask_mail import Message, Mail  # Import the mail instance here
from dotenv import load_dotenv
from datetime import timedelta


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


load_dotenv()







auth = Blueprint('auth', __name__, url_prefix='/auth')

cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key=os.environ.get('CLOUDINARY_API_KEY'),
    api_secret=os.environ.get('CLOUDINARY_API_SECRET'),
)

def validate_password(password):
    # Check password length
    if len(password) < 6:
        return "Password must be at least 6 characters long."

    # Check for at least one uppercase letter
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."

    # Check for at least one number
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."

    # Check for at least one special character
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."

    # If all checks pass
    return None




# Test
@auth.get("/test")
def test():
    return jsonify({"message": "Test successful"}), http_status_codes.HTTP_200_OK





# Register user
@auth.post("/register_user")
def register():
    try:
        mail = current_app.extensions.get('mail')
        if not mail:
            raise RuntimeError("Flask-Mail not initialized")

        username = request.json.get('username')
        first_name = request.json.get('first_name')
        last_name = request.json.get('last_name')
        email = request.json.get('email')
        password = request.json.get('password')
        confirm_password = request.json.get('confirm_password')
        phone_number = request.json.get('phone_number')
        profile_pic = request.json.get('profile_pic')
        
        # Validate password
        password_error = validate_password(password)
        if password_error:
            return jsonify({"message": password_error}), http_status_codes.HTTP_400_BAD_REQUEST
        
        # Passwords don't match
        if password != confirm_password:
            return jsonify({"message": "Passwords don't match"}), http_status_codes.HTTP_400_BAD_REQUEST

        # Check if email is valid
        if not validators.email(email):
            return jsonify({"message": "Invalid email"}), http_status_codes.HTTP_400_BAD_REQUEST

        # Check if email exist
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"message": "User already exists"}), http_status_codes.HTTP_400_BAD_REQUEST

            # Upload profile picture to Cloudinary
        cloudinary_url = None
        if profile_pic:
            try:
                upload_result = cloudinary.uploader.upload(profile_pic)
                cloudinary_url = upload_result.get("secure_url")
            except Exception as e:
                return (
                    jsonify({"message": f"Error uploading image: {str(e)}"}),
                    http_status_codes.HTTP_400_BAD_REQUEST,
                )

        # Hash password
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        # Generate email verification token
        s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        verification_token = s.dumps(email, salt="email-verification-salt")

        # Create user
        user = User(
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email.lower(),
            password=hashed_password,
            phone_number=phone_number,
            profile_pic=cloudinary_url,
            verification_token=verification_token,
        )
        db.session.add(user)
        db.session.commit()

    # Send Verification Email
        verification_url = (
        f"https://service-nest.onrender.com/auth/verify/{verification_token}"
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