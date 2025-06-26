import cloudinary
import cloudinary.uploader
import datetime
import logging
import os
import random
import re
import string
import traceback
import validators
from datetime import timedelta
from dotenv import load_dotenv
from flask import (
    Flask,
    request,
    session,
    url_for,
    redirect,
    Blueprint,
    jsonify,
    current_app,
)
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    current_user,
)
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask_mail import Message, Mail  # Import the mail instance here
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer, BadSignature
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from urllib.parse import unquote
from werkzeug.security import generate_password_hash, check_password_hash

import src.cloudinary_config
from src.constants import http_status_codes
from src.constants.env_constant import (
    FRONTEND_VERIFICATION_URL,
    FRONTEND_LOGIN_URL,
    EXCEPTION_MESSAGE,
)
from src.logger import logger
from src.model.database import db, User, Products, Category, Cart
from src.services.mail import send_mail
from src.utils import (
    validate_password,
    is_valid_email,
    validate_phone_number,
    generate_otp,
)
from src.utils.util import return_response
from src.constants.status_message import StatusMessage

# from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, current_user

load_dotenv()


auth = Blueprint("auth", __name__)


# Test
@auth.get("/test")
def test():
    return return_response(
        http_status_codes.HTTP_200_OK,
        status=StatusMessage.SUCCESS,
        message="Test successful",
    )


@auth.post("/register_user")
def register():
    # Validate input data
    username = request.json.get("username")
    first_name = request.json.get("first_name")
    last_name = request.json.get("last_name")
    email = request.json.get("email")
    password = request.json.get("password")
    confirm_password = request.json.get("confirm_password")
    phone_number = request.json.get("phone_number")

    if not all(
        [
            username,
            first_name,
            last_name,
            email,
            password,
            confirm_password,
            phone_number,
        ]
    ):
        return return_response(
            http_status_codes.HTTP_400_BAD_REQUEST,
            status=StatusMessage.FAILED,
            message="All fields are required",
        )

    email = email.lower()

    # Validate password
    password_error = validate_password(password)
    if password_error:
        return return_response(
            http_status_codes.HTTP_400_BAD_REQUEST,
            status=StatusMessage.FAILED,
            message=password_error,
        )

    # Passwords don't match
    if password != confirm_password:
        return return_response(
            http_status_codes.HTTP_400_BAD_REQUEST,
            status=StatusMessage.FAILED,
            message="Passwords don't match",
        )

    # Check if email is valid
    email_res = is_valid_email(email)

    if not email_res:
        return return_response(
            http_status_codes.HTTP_400_BAD_REQUEST,
            status=StatusMessage.FAILED,
            message="Invalid email",
        )

    # Check if email or username already exists
    try:
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="User already exists",
            )

        existing_username = User.query.filter_by(username=username).first()
        logger.info(f"Existing username query result: {existing_username}")
        if existing_username:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="User with this username already exists",
            )
    except Exception as e:
        logger.error(f"Database query error: {str(e)}")
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )

    phone_res = validate_phone_number(phone_number)

    if phone_res:
        return return_response(
            http_status_codes.HTTP_400_BAD_REQUEST,
            status=StatusMessage.FAILED,
            message=phone_res,
        )

    try:
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
            verification_token=verification_token,
        )
        db.session.add(user)
        db.session.commit()

        send_mail(
            {
                "email": email,
                "subject": "Email Verification",
                "template": "email_verification.html",
                "verification_url": FRONTEND_VERIFICATION_URL + verification_token,
                "name": f"{last_name} {first_name}",
            }
        )

        logger.info("Verification email sent successfully")
        return return_response(
            http_status_codes.HTTP_201_CREATED,
            status=StatusMessage.SUCCESS,
            message="User registered successfully. Please verify your email.",
            user=user.to_dict(),
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


@auth.get("/verify/<token>")
def verify_email(token):
    try:
        s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        logger.info(f"Received token: {token}")  # Debug

        # Decode the token from the URL if necessary
        token = unquote(token)  # URL decode the token if it was URL-encoded

        email = s.loads(token, salt="email-verification-salt", max_age=3600)  # 24 hours

        user = User.query.filter_by(email=email).first()
        if not user:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="User not found.",
            )

        if user.email_verified:
            return redirect("https://servicenest.netlify.app/login")

        # Validate the token against the database
        logger.info(f"Stored token: {user.verification_token}")  # Debug
        logger.info(f"Received token: {token}")  # Debug

        if user.verification_token != token:
            logger.info("Invalid or expired token.")
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Invalid or expired token.",
            )

        logger.info(f"User {user.email} verification status: {user.email_verified}")

        user.email_verified = True
        user.verification_token = None
        db.session.commit()

        send_mail(
            {
                "email": email,
                "subject": "Welcome",
                "template": "welcome.html",
                "name": f"{user.last_name} {user.first_name}",
            }
        )

        logger.info("Redirecting to frontend")
        # Redirect to the login page after sending the email
        return redirect(FRONTEND_LOGIN_URL)

    except SignatureExpired:
        return return_response(
            http_status_codes.HTTP_400_BAD_REQUEST,
            status=StatusMessage.FAILED,
            message="Token has expired.",
        )
    except BadSignature:
        return return_response(
            http_status_codes.HTTP_400_BAD_REQUEST,
            status=StatusMessage.FAILED,
            message="Invalid token.",
        )
    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# Resend Email Verification
@auth.post("/resend-verification")
def resend_verification():
    email = request.json.get("email")
    if not email:
        return return_response(
            http_status_codes.HTTP_400_BAD_REQUEST,
            status=StatusMessage.FAILED,
            message="Email is required.",
        )
    user = User.query.filter_by(email=email.lower()).first()

    if not user:
        return return_response(
            http_status_codes.HTTP_404_NOT_FOUND,
            status=StatusMessage.FAILED,
            message="User not found.",
        )

    if user.email_verified:
        return return_response(
            http_status_codes.HTTP_400_BAD_REQUEST,
            status=StatusMessage.FAILED,
            message="Email is already verified.",
        )

    # Generate a new token
    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    new_token = s.dumps(email, salt="email-verification-salt")

    # Update the user's verification token
    user.verification_token = new_token
    db.session.commit()

    send_mail(
        {
            "email": email,
            "subject": "Email Verification",
            "template": "email_verification.html",
            "verification_url": FRONTEND_VERIFICATION_URL + new_token,
            "name": f"{user.last_name} {user.first_name}",
        }
    )

    return return_response(
        http_status_codes.HTTP_200_OK,
        status=StatusMessage.SUCCESS,
        message="Verification email resent.",
    )


@auth.post("/login")
def login():
    email = request.json.get("email", "")
    password = request.json.get("password", "")

    if not email or not password:
        return return_response(
            http_status_codes.HTTP_400_BAD_REQUEST,
            status=StatusMessage.FAILED,
            message="Email and password are required",
        )

    user = User.query.filter_by(email=email.lower()).first()

    if not user or not check_password_hash(user.password, password):
        return return_response(
            http_status_codes.HTTP_401_UNAUTHORIZED,
            status=StatusMessage.FAILED,
            message="Invalid email or password",
        )

    if not user.email_verified:
        return return_response(
            http_status_codes.HTTP_401_UNAUTHORIZED,
            status=StatusMessage.FAILED,
            message="Email is not verified",
        )

    access_token = create_access_token(identity=user.id, fresh=True)
    refresh_token = create_refresh_token(identity=user.id)

    return return_response(
        http_status_codes.HTTP_200_OK,
        status=StatusMessage.SUCCESS,
        message="Login successful",
        **{
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "is_admin": user.is_admin,
            },
        },
    )


@auth.post("/request_reset_password")
def request_reset_password():
    try:
        email = request.json.get("email").lower()

        if not email:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Email is required",
            )

        user = User.query.filter_by(email=email).first()

        if not user:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="User not found",
            )

        otp = generate_otp()

        user.reset_otp = otp
        user.otp_expiration = datetime.datetime.now() + datetime.timedelta(
            minutes=10
        )  # OTP valid for 10 minutes
        db.session.commit()

        send_mail(
            {
                "email": email,
                "subject": "Reset Password",
                "template": "reset_password.html",
                "otp": otp,
                "name": f"{user.last_name} {user.first_name}",
            }
        )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Reset password email sent",
        )

    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


@auth.post("/reset_password")
def reset_password():
    try:
        email = request.json.get("email").lower()
        otp = request.json.get("otp")
        new_password = request.json.get("new_password")

        if not email or not otp or not new_password:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Email, OTP, and new password are required",
            )

        user = User.query.filter_by(email=email.lower()).first()

        if not user:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="User not found",
            )

        if user.reset_otp != otp:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Invalid OTP",
            )

        if user.otp_expiration < datetime.datetime.now():
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="OTP has expired",
            )

        user.password = generate_password_hash(new_password, method="pbkdf2:sha256")
        user.reset_otp = None
        user.otp_expiration = None
        db.session.commit()

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Password reset successfully",
        )
    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )
