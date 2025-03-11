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
            email=email,
            password=hashed_password,
            phone_number=phone_number,
            profile_pic=cloudinary_url,
            verification_token=verification_token,
        )
        db.session.add(user)
        db.session.commit()

        return jsonify({"message": "User registered successfully", "user": user.to_dict()}), http_status_codes.HTTP_201_CREATED

    except Exception as e:
        logging.error(traceback.format_exc())
        return jsonify({"message": "Error registering user"}), http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR
    