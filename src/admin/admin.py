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
from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask_mail import Message, Mail  # Import the mail instance here
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, BadSignature
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.exc import SQLAlchemyError
from urllib.parse import quote
from urllib.parse import unquote
from werkzeug.security import generate_password_hash, check_password_hash

from src.constants import http_status_codes
from src.extentions.extensions import jwt, mail, cors  # Ensure this import is correct
from src.model.database import db, User, Category, Products, Cart

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Blueprint setup
admin = Blueprint("admin", __name__, url_prefix="/admin")

# Cloudinary Config
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
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


from functools import wraps
from flask import jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from http import HTTPStatus


from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    verify_jwt_in_request,
    get_jwt,
)
from http import HTTPStatus


def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            try:
                print("Authorization Header:", request.headers.get("Authorization"))

                verify_jwt_in_request()
                jwt_data = get_jwt()
                user_id = get_jwt_identity()

                if not jwt_data.get("is_admin", False):
                    return (
                        jsonify({"message": "Admin access required"}),
                        HTTPStatus.FORBIDDEN,
                    )

                user = User.query.get(user_id)
                if not user:
                    return jsonify({"message": "User not found"}), HTTPStatus.NOT_FOUND

                if not hasattr(user, "is_admin") or not user.is_admin:
                    return (
                        jsonify({"message": "Admin privileges required"}),
                        HTTPStatus.FORBIDDEN,
                    )

                return fn(*args, **kwargs)

            except Exception as e:
                return (
                    jsonify({"message": "Authentication failed", "error": str(e)}),
                    HTTPStatus.UNAUTHORIZED,
                )

        return decorator

    return wrapper


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
        return (
            jsonify({"message": password_error}),
            http_status_codes.HTTP_400_BAD_REQUEST,
        )

    if password != confirm_password:
        return (
            jsonify({"message": "Passwords do not match"}),
            http_status_codes.HTTP_400_BAD_REQUEST,
        )

    # Email validation
    if not validators.email(email):
        return (
            jsonify({"message": "Invalid email address"}),
            http_status_codes.HTTP_400_BAD_REQUEST,
        )

    # Check if email already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return (
            jsonify({"message": "Email already in use"}),
            http_status_codes.HTTP_409_CONFLICT,
        )

    if username:
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return (
                jsonify({"message": "Username already in use"}),
                http_status_codes.HTTP_409_CONFLICT,
            )

    if first_name:
        existing_user = User.query.filter_by(first_name=first_name).first()
        if existing_user:
            return (
                jsonify({"message": "First name already in use"}),
                http_status_codes.HTTP_409_CONFLICT,
            )

    if last_name:
        existing_user = User.query.filter_by(last_name=last_name).first()
        if existing_user:
            return (
                jsonify({"message": "Last name already in use"}),
                http_status_codes.HTTP_409_CONFLICT,
            )

    if phone_number:
        existing_user = User.query.filter_by(phone_number=phone_number).first()
        if existing_user:
            return (
                jsonify({"message": "Phone number already in use"}),
                http_status_codes.HTTP_409_CONFLICT,
            )

    # Hash password
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

    # Generate email verification token
    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
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
        is_admin=True,
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
                "Verify Your Email",
                sender=os.getenv("MAIL_USERNAME"),
                recipients=[email],
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
            return (
                jsonify(
                    {
                        "message": "Admin registered successfully. Please verify your email.",
                        "admin": new_user.to_dict(),
                    }
                ),
                http_status_codes.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            return (
                jsonify({"message": f"Error sending email: {str(e)}"}),
                http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    except Exception as e:
        logger.error(f"Error during registration: {str(e)}")
        logger.error(traceback.format_exc())
        return (
            jsonify({"message": "Error registering user"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# Send Email Verification
@admin.get("/verify_admin/<string:token>")
def verify_email(token):
    """Verify email using the token."""
    try:

        mail = current_app.extensions.get("mail")
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

        return (
            jsonify({"message": "Email verified successfully."}),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        return (
            jsonify({"message": f"Token verification failed: {str(e)}"}),
            http_status_codes.HTTP_400_BAD_REQUEST,
        )


# Resend Email Verification
@admin.post("/resend-verification_admin")
def resend_verification():
    email = request.json.get("email")
    user = Users.query.filter_by(email=email).first()

    if not user:
        return (
            jsonify({"message": "User not found."}),
            http_status_codes.HTTP_404_NOT_FOUND,
        )

    if user.email_verified:
        return (
            jsonify({"message": "Email is already verified."}),
            http_status_codes.HTTP_400_BAD_REQUEST,
        )

    # Generate a new token
    s = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    new_token = s.dumps(user.email, salt="email-verification-salt")

    user.verification_token = new_token
    db.session.commit()

    verification_url = f"http://your-domain.com/verify/{new_token}"
    try:
        msg = Message(
            "Verify Your Email", sender=os.getenv("MAIL_USERNAME"), recipients=[email]
        )
        msg.body = f"Hi {user.first_name},\n\nPlease verify your email by clicking the link below:\n{verification_url}\n\nThank you!"
        mail.send(msg)  # Use the mail instance directly
    except Exception as e:
        return (
            jsonify({"message": f"Error sending email: {str(e)}"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return (
        jsonify({"message": "Verification email resent."}),
        http_status_codes.HTTP_200_OK,
    )


# Admin login
@admin.post("/login_admin")
def login():
    try:
        if not request.is_json:
            return (
                jsonify({"message": "Missing JSON in request"}),
                HTTPStatus.BAD_REQUEST,
            )

        email = request.json.get("email", "").strip()
        password = request.json.get("password", "")

        if not email or not password:
            return (
                jsonify({"message": "Email and password are required"}),
                HTTPStatus.BAD_REQUEST,
            )

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            return (
                jsonify({"message": "Invalid email or password"}),
                HTTPStatus.UNAUTHORIZED,
            )

        # Verify admin status before issuing tokens
        if not hasattr(user, "is_admin") or not user.is_admin:
            return jsonify({"message": "Admin access required"}), HTTPStatus.FORBIDDEN

        # Create tokens with additional claims
        additional_claims = {"is_admin": user.is_admin, "email": user.email}

        access_token = create_access_token(
            identity=user.id, fresh=True, additional_claims=additional_claims
        )
        refresh_token = create_refresh_token(
            identity=user.id, additional_claims=additional_claims
        )

        return (
            jsonify(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "id": user.id,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "email": user.email,
                        "is_admin": user.is_admin,
                    },
                }
            ),
            HTTPStatus.OK,
        )

    except Exception as e:
        return (
            jsonify({"message": "Login failed", "error": str(e)}),
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@admin.post("/add_category")
@admin_required()
def add_category():
    try:
        data = request.get_json()
        name = data.get("name")
        image = data.get("image")
        print(name, image, "IMAGEEEEEEEEEEEETTTTTTTTT", "BEFORE")

        # Validate required fields
        if not name:
            return (
                jsonify({"message": "Category name is required"}),
                http_status_codes.HTTP_400_BAD_REQUEST,
            )

        if not image:
            return (
                jsonify({"message": "Category image is required"}),
                http_status_codes.HTTP_400_BAD_REQUEST,
            )
        print("I AM HEREEEEEEE")

        # Check for duplicate category name
        existing_category = Category.query.filter_by(name=name).first()

        if existing_category:
            return (
                jsonify({"message": "This category name already exists"}),
                http_status_codes.HTTP_409_CONFLICT,
            )

        # Upload image to Cloudinary
        try:
            upload_result = cloudinary.uploader.upload(image)
            image_url = upload_result.get("secure_url")
        except Exception as e:
            logger.error(f"Error uploading image to Cloudinary: {str(e)}")
            return (
                jsonify({"message": "Failed to upload image"}),
                http_status_codes.HTTP_400_BAD_REQUEST,
            )

        # Create new category
        new_category = Category(name=name, image=image_url)

        db.session.add(new_category)
        db.session.commit()

        return (
            jsonify(
                {
                    "message": "New category added successfully",
                    "category": {
                        "id": new_category.id,
                        "name": new_category.name,
                        "image": new_category.image,
                    },
                }
            ),
            http_status_codes.HTTP_201_CREATED,
        )

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding category: {str(e)}")
        print(f"{str(e)}", "ERROR FROM ADMIN")
        return (
            jsonify({"message": "An error occurred while adding category"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@admin.delete("/delete_category")
@admin_required()
def delete_category():
    category_id = request.json.get("category_id")
    if not category_id:
        return (
            jsonify({"message": "Category ID is required"}),
            http_status_codes.HTTP_400_BAD_REQUEST,
        )

    category = Category.query.get(category_id)
    if not category:
        return (
            jsonify({"message": "Category not found"}),
            http_status_codes.HTTP_404_NOT_FOUND,
        )

    try:
        products = Products.query.filter_by(category_id=category_id).all()

        for product in products:
            # First clean up dependent carts
            carts = Cart.query.filter_by(product_id=product.id).all()
            for cart in carts:
                db.session.delete(cart)

            db.session.delete(product)

        db.session.delete(category)
        db.session.commit()

        return (
            jsonify(
                {"message": "Category, products, and linked carts deleted successfully"}
            ),
            http_status_codes.HTTP_200_OK,
        )

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error deleting category: {str(e)}")
        print(str(e), "ERRORRRRRRR")
        return (
            jsonify({"message": "Error deleting category"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# Update Categories
@admin.put("/update_category/<string:id>")
@admin_required()
def update_category(id):

    category = Category.query.get(id)

    if not category:
        return (
            jsonify({"message": "Category not found"}),
            http_status_codes.HTTP_404_NOT_FOUND,
        )

    data = request.json
    new_cat = data.get("name", category.name)
    new_image = data.get("image", category.image)
    # if not new_cat:
    #     return jsonify({"message": "Category name is required"}), http_status_codes.HTTP_400_BAD_REQUEST

    existing_category = Category.query.filter(
        Category.name == new_cat, Category.id != id
    ).first()
    if existing_category:
        return (
            jsonify({"message": "This category name already exists"}),
            http_status_codes.HTTP_409_CONFLICT,
        )

    try:
        # Update the category name
        category.name = new_cat
        category.image = new_image
        db.session.commit()

        return (
            jsonify(
                {
                    "message": "Category updated successfully",
                    "category": {"id": category.id, "name": category.name},
                }
            ),
            http_status_codes.HTTP_200_OK,
        )

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Error updating category: {str(e)}")
        return (
            jsonify({"message": "Error updating category"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@admin.post("/add_product")
@admin_required()
def add_product():
    try:
        data = request.json

        name = data.get("name")
        price = data.get("price")
        color = data.get("color")
        model = data.get("model")
        image = data.get("image")
        category_id = data.get("category_id")
        description = (data.get("description"),)

        existing_product = Products.query.filter_by(name=name).first()
        if existing_product:
            return (
                jsonify({"error": "Product already exists"}),
                http_status_codes.HTTP_409_CONFLICT,
            )

        if not all([name, price, color, model, category_id, image, description]):
            return (
                jsonify({"error": "Missing required fields"}),
                http_status_codes.HTTP_400_BAD_REQUEST,
            )

        category = Category.query.get(category_id)
        if not category:
            return (
                jsonify({"error": "Invalid category_id"}),
                http_status_codes.HTTP_400_BAD_REQUEST,
            )

        # Upload profile picture to Cloudinary
        cloudinary_url = None
        if image:
            try:
                upload_result = cloudinary.uploader.upload(image)
                cloudinary_url = upload_result.get("secure_url")
            except Exception as e:
                return (
                    jsonify({"message": f"Error uploading image: {str(e)}"}),
                    http_status_codes.HTTP_400_BAD_REQUEST,
                )

        new_product = Products(
            name=name,
            price=float(price),
            color=color,
            model=model,
            image=cloudinary_url,
            category_id=category_id,
            description=description,
            out_of_stock=data.get("out_of_stock", False),
            specification_1=data.get("specification_1"),
            specification_2=data.get("specification_2"),
            specification_4=data.get("specification_4"),
            specification_5=data.get("specification_5"),
            specification_6=data.get("specification_6"),
            specification_7=data.get("specification_7"),
            specification_8=data.get("specification_8"),
            specification_9=data.get("specification_9"),
            specification_10=data.get("specification_10"),
            specification_11=data.get("specification_11"),
            specification_12=data.get("specification_12"),
            specification_13=data.get("specification_13"),
            specification_14=data.get("specification_14"),
            specification_15=data.get("specification_15"),
        )

        db.session.add(new_product)
        db.session.commit()

        return (
            jsonify(
                {
                    "message": "Product added successfully",
                    "product": new_product.to_dict(),
                }
            ),
            201,
        )

    except ValueError:
        return jsonify({"error": "Invalid price format"}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# Delete a product
@admin.delete("/delete_product/<string:id>")
@admin_required()
def delete_product(id):
    try:
        # Query the product by its ID
        product = Products.query.get(id)

        # Check if the product exists
        if not product:
            return (
                jsonify({"error": "Product not found"}),
                http_status_codes.HTTP_404_NOT_FOUND,
            )

        # Delete the product
        db.session.delete(product)
        db.session.commit()

        return (
            jsonify({"message": "Product deleted successfully"}),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        return (
            jsonify({"error": str(e)}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# Update a product
@admin.put("/update_product/<string:id>")
@admin_required()
def update_product(id):
    try:
        # Query the product by its ID
        product = Products.query.get(id)

        # Check if the product exists
        if not product:
            return (
                jsonify({"error": "Product not found"}),
                http_status_codes.HTTP_404_NOT_FOUND,
            )

        # Get the request data
        data = request.json

        # Update only the fields that are provided in the request, keeping existing values otherwise
        product.name = data.get("name", product.name)
        product.price = data.get("price", product.price)
        product.color = data.get("color", product.color)
        product.model = data.get("model", product.model)
        product.image = data.get("image", product.image)
        product.category_id = data.get("category_id", product.category_id)
        product.description = data.get("description", product.description)
        product.out_of_stock = data.get("out_of_stock", product.out_of_stock)
        product.specification_1 = data.get("specification_1", product.specification_1)
        product.specification_2 = data.get("specification_2", product.specification_2)
        product.specification_3 = data.get("specification_3", product.specification_3)
        product.specification_4 = data.get("specification_4", product.specification_4)
        product.specification_5 = data.get("specification_5", product.specification_5)
        product.specification_6 = data.get("specification_6", product.specification_6)
        product.specification_7 = data.get("specification_7", product.specification_7)
        product.specification_8 = data.get("specification_8", product.specification_8)
        product.specification_9 = data.get("specification_9", product.specification_9)
        product.specification_10 = data.get(
            "specification_10", product.specification_10
        )
        product.specification_11 = data.get(
            "specification_11", product.specification_11
        )
        product.specification_12 = data.get(
            "specification_12", product.specification_12
        )
        product.specification_13 = data.get(
            "specification_13", product.specification_13
        )
        product.specification_14 = data.get(
            "specification_14", product.specification_14
        )
        product.specification_15 = data.get(
            "specification_15", product.specification_15
        )

        db.session.commit()

        return (
            jsonify(
                {
                    "message": "Product updated successfully",
                    "product": product.to_dict(),
                }
            ),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        return (
            jsonify({"error": str(e)}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# View single product
@admin.get("/single_product/<string:id>")
@admin_required()
def single_product(id):
    try:
        # Query the product by its ID
        product = Products.query.get(id)

        # Check if the product exists
        if not product:
            return (
                jsonify({"error": "Product not found"}),
                http_status_codes.HTTP_404_NOT_FOUND,
            )

        # Return the product details
        return (
            jsonify(
                {
                    "message": "Product retrieved successfully",
                    "product": product.to_dict(),
                }
            ),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        return (
            jsonify({"error": str(e)}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@admin.get("/single_gadget/<string:id>")
@admin_required()
def single_gadgets(id):
    try:
        # Query the product by its ID
        gadget = Products.query.get(id)

        # Check if the product exists
        if not gadget:
            return jsonify({"error": "Gadget not found"}), 404

        # Return the product details
        return (
            jsonify(
                {"message": "Gadget retrieved successfully", "gadget": gadget.to_dict()}
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Get all categories
@admin.get("/all_categories")
@admin_required()
def get_all_categories():
    try:
        if not current_user.is_admin:
            return (
                jsonify({"error": "You are not an admin."}),
                http_status_codes.HTTP_401_UNAUTHORIZED,
            )

        categories = Category.query.all()
        return (
            jsonify(
                {
                    "message": "Categories retrieved successfully",
                    "categories": [category.to_dict() for category in categories],
                }
            ),
            200,
        )

    except Exception as e:
        return (
            jsonify({"error": str(e)}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@admin.get("/product_by_category/<string:category_id>")
@admin_required()
def get_product_by_category(category_id):
    try:
        category = Category.query.get(category_id)
        if not category:
            return (
                jsonify({"error": "Category not found"}),
                http_status_codes.HTTP_404_NOT_FOUND,
            )

        gadgets = Products.query.filter_by(category_id=category_id).all()

        if not gadgets:
            return (
                jsonify(
                    {"message": "No gadgets found in this category", "gadgets": []}
                ),
                200,
            )

        gadgets_list = [gadget.to_dict() for gadget in gadgets]

        return (
            jsonify(
                {"message": "Gadgets retrieved successfully", "gadgets": gadgets_list}
            ),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        return (
            jsonify({"error": str(e)}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# All products
@admin.get("/all_products")
@admin_required()
def all_products():
    try:
        query = request.args.get("query", "")
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 10))

        products_query = Products.query.filter(
            Products.name.ilike(f"%{query}%")
        ).paginate(page=page, per_page=per_page, error_out=False)

        total_pages = products_query.pages
        has_next = products_query.has_next
        has_prev = products_query.has_prev

        return (
            jsonify(
                {
                    "message": "Products retrieved successfully",
                    "products": [product.to_dict() for product in products_query.items],
                    "total_pages": total_pages,
                    "total_items": products_query.total,
                    "page": page,
                    "per_page": per_page,
                    "has_next": has_next,
                    "has_prev": has_prev,
                }
            ),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        return (
            jsonify({"error": str(e)}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )
