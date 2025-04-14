from flask import Flask, request, session, url_for, redirect, Blueprint, jsonify, current_app
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import validators, re, logging, os, random, string, datetime, traceback
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, current_user
import cloudinary
from itsdangerous import URLSafeTimedSerializer, BadSignature
import cloudinary.uploader
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from src.model.database import db, User, Products, Category
from src.constants import http_status_codes
from flask_mail import Message, Mail  # Import the mail instance here
from dotenv import load_dotenv
from datetime import timedelta
from urllib.parse import unquote
# from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, current_user


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





@auth.post("/register_user")
def register():
    # Validate input data
    username = request.json.get('username')
    first_name = request.json.get('first_name')
    last_name = request.json.get('last_name')
    email = request.json.get('email')
    password = request.json.get('password')
    confirm_password = request.json.get('confirm_password')
    phone_number = request.json.get('phone_number')

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

    # Check if email or username already exists
    try:
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return jsonify({"message": "User already exists"}), http_status_codes.HTTP_400_BAD_REQUEST

        existing_username = User.query.filter_by(username=username).first()
        logger.info(f"Existing username query result: {existing_username}")
        if existing_username:
            return jsonify({"message": "User with this username already exists"}), http_status_codes.HTTP_400_BAD_REQUEST
    except Exception as e:
        logger.error(f"Database query error: {str(e)}")
        return jsonify({"message": "Database error"}), http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR
    
    if not phone_number.isdigit():
        return jsonify({"message": "Invalid phone number"}), http_status_codes.HTTP_400_BAD_REQUEST
    
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

        # Send Verification Email
        verification_url = f"https://chi-icon.onrender.com/auth/verify/{verification_token}"
        mail = current_app.extensions.get('mail')
        if not mail:
            raise RuntimeError("Flask-Mail not initialized")

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
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                    }}
                    .container {{
                        background-color: #ffffff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                        max-width: 600px;
                        width: 100%;
                        text-align: center;
                    }}
                    img {{
                        width: 250px;
                        height: auto;
                        display: block;
                        margin: auto;
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
        db.session.rollback()
        logger.error(f"Error during registration: {str(e)}")
        logger.error(f"Exception type: {type(e).__name__}")
        logger.error(f"Exception args: {e.args}")
        logger.error(traceback.format_exc())
        return jsonify({"message": "Error registering user", "error": str(e)}), http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR
    
    
    
    
    
@auth.get("/verify/<token>")
def verify_email(token):
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
        
        # Prepare the email message
        msg = Message(
            f"You’re in, {user.first_name} {user.last_name}! Let us show you around",
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
                    width: 100%; 
                    text-align: center;  
                }}
                .container_2{{
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                    max-width: 600px;
                    width: 100%; 
                    text-align: center; 
                    border: 1px solid whitesmoke;
                }}
                img {{
                    width: 250px;
                    height: auto;
                    display: block;
                    margin: auto
                }}
                image_2 {{
                    width: 500px;
                    height: 150px;
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
                .text{{
                    padding: 10px 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <img src="https://res.cloudinary.com/de8pdqpun/image/upload/v1737536089/logo_new_upsyih.svg" alt="Company Logo" class="image_2"> 
                <h2>Welcome to Chi_Icon {user.first_name} {user.last_name},</h2>
                <p>You've just taken the first step towards finding your perfect product of your choice. To kick things off, we'd like to show you around. Here are a few important areas on the site:</p>
                <div class="container_2">
                <p>Thank you!</p>
            </div>
                </body>
            </html>
                """

        # Send the email
        try:
            mail.send(msg)
            print("Email sent successfully.")
        except Exception as e:
            print("Email delivery failed.", e)
            logging.error(f"Email delivery failed for user {user.email}: {str(e)}")
            return (
                jsonify({"message": "Email sent but delivery failed."}),
                http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        print("Redirecting to frontend")
        # Redirect to the login page after sending the email
        return redirect("https://servicenest.netlify.app/login")

    except SignatureExpired:
        return (
            jsonify({"message": "Token has expired."}),
            http_status_codes.HTTP_400_BAD_REQUEST,
        )
    except BadSignature:
        return (
            jsonify({"message": "Invalid token."}),
            http_status_codes.HTTP_400_BAD_REQUEST,
        )
    except Exception as e:
        logging.error(f"Token verification failed: {str(e)}")
        return (
            jsonify({"message": "An unexpected error occurred."}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        
        
        
        
        
        
        
# Resend Email Verification
@auth.post("/resend-verification")
def resend_verification():
    
    mail = current_app.extensions.get('mail')
    if not mail:
            raise RuntimeError("Flask-Mail not initialized")
    
    
    email = request.json.get("email")
    user = User.query.filter_by(email=email).first()

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
    new_token = s.dumps(email, salt="email-verification-salt")

    # Update the user's verification token
    user.verification_token = new_token
    db.session.commit()

    verification_url = f"https://chi-icon.onrender.com/auth/verify/{new_token}"
    try:
        msg = Message(
            "Verify Your Email",
            sender=os.getenv("MAIL_USERNAME"),
            recipients=[email],
        )
        msg.body = f"Hi {user.first_name},\n\nPlease verify your email by clicking the link below:\n{verification_url}\n\nThank you!"
        mail.send(msg)
    except Exception as e:
        return (
            jsonify({"message": f"Error sending email: {str(e)}"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return (
        jsonify({"message": "Verification email resent."}),
        http_status_codes.HTTP_200_OK,
    )






@auth.post("/login")
def login():
    email = request.json.get("email", "").lower()
    password = request.json.get("password", "")

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return (
            jsonify({"message": "Invalid email or password"}),
            http_status_codes.HTTP_401_UNAUTHORIZED,
        )

    if not user.email_verified:
        return (
            jsonify({"message": "Email is not verified"}),
            http_status_codes.HTTP_401_UNAUTHORIZED,
        )

    access_token = create_access_token(identity=user.id, fresh=True)
    refresh_token = create_refresh_token(identity=user.id)

    return (
        jsonify(
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.email,
                },
            }
        ),
        http_status_codes.HTTP_200_OK,
    )
    
    
    
    
    
    
    
    
    
    
    
    
# Generate OTP for password reset
def generate_otp():
    return str(random.randint(1000, 9999))


# Send email with OTP
def send_otp(email, otp):
    
    mail = current_app.extensions.get('mail')
    if not mail:
            raise RuntimeError("Flask-Mail not initialized")
    
    subject = "Password Reset OTP"
    message = f"Your OTP for password reset is: {otp}"
    msg = Message(subject=subject, recipients=[email], body=message)
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False



def otp_reset_successful(email, otp):
    mail = current_app.extensions.get('mail')
    if not mail:
        raise RuntimeError('Flask-Mail not initialized')
    
    subject = "Password Reset Successful"
    message = f"Your password has been reset successfully"
    msg = Message(subject=subject, recipients=[email], body=message)
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False




@auth.post("/request_reset_password")
def request_reset_password():
    mail = current_app.extensions.get('mail')
    if not mail:
            raise RuntimeError("Flask-Mail not initialized")
    
    
    email = request.json.get("email").lower()

    if not email:
        return (
            jsonify({"message": "Email is required"}),
            http_status_codes.HTTP_400_BAD_REQUEST,
        )

    user = User.query.filter_by(email=email).first()

    if not user:
        return (
            jsonify({"message": "User not found"}),
            http_status_codes.HTTP_404_NOT_FOUND,
        )

    otp = generate_otp()

    user.reset_otp = otp
    user.otp_expiration = datetime.datetime.utcnow() + datetime.timedelta(
        minutes=10
    )  # OTP valid for 10 minutes
    db.session.commit()

    if send_otp(email, otp):
        return (
            jsonify({"message": "Reset OTP sent to your email"}),
            http_status_codes.HTTP_200_OK,
        )
    else:
        return (
            jsonify({"message": "Failed to send OTP"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@auth.post("/reset_password")
def reset_password():
    mail = current_app.extensions.get('mail')
    if not mail:
            raise RuntimeError("Flask-Mail not initialized")
    
    
    email = request.json.get("email").lower()
    otp = request.json.get("otp")
    new_password = request.json.get("new_password")

    if not email or not otp or not new_password:
        return (
            jsonify({"message": "Email, OTP, and new password are required"}),
            http_status_codes.HTTP_400_BAD_REQUEST,
        )

    user = User.query.filter_by(email=email).first()

    if not user:
        return (
            jsonify({"message": "User not found"}),
            http_status_codes.HTTP_404_NOT_FOUND,
        )

    if user.reset_otp != otp:
        return (
            jsonify({"message": "Invalid OTP"}),
            http_status_codes.HTTP_400_BAD_REQUEST,
        )

    if user.otp_expiration < datetime.datetime.utcnow():
        return (
            jsonify({"message": "OTP has expired"}),
            http_status_codes.HTTP_400_BAD_REQUEST,
        )

    user.password = generate_password_hash(new_password, method="pbkdf2:sha256")
    user.reset_otp = None
    user.otp_expiration = None
    db.session.commit()
    
    if otp_reset_successful(email, otp):
        return (
        jsonify({"message": "Password reset successfully"}),
        http_status_codes.HTTP_200_OK,
    )


    

# Get all products paginated
@auth.get("/get_all_products")
# @jwt_required()
def get_all_products():
    try:
        query = request.args.get("query", "")
        page = request.args.get("page", 1, type=int)
        per_page = 10
        
        products_query = (
            Products.query
            .filter(Products.name.ilike(f"%{query}%"))
            .order_by(Products.created_at.desc()) 
            .paginate(page=page, per_page=per_page)
        )
        
        products = products_query.items
        total_pages = products_query.pages
        has_next = products_query.has_next
        has_prev = products_query.has_prev
        
        products_list = [product.to_dict() for product in products]
        
        return jsonify({
            'message': 'Products retrieved successfully',
            'products': products_list,
            'total_pages': total_pages,
            'has_next': has_next,
            'has_prev': has_prev
        }), http_status_codes.HTTP_200_OK
        
    except Exception as e:
        return jsonify({'error': str(e)}), http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR
    
    
    
    
# Get single product
@auth.get("/single_product/<string:id>")
# @jwt_required()
def get_single_product(id):
    try:
        # if not current_user:
        #     return jsonify({"message": "User not found"}), http_status_codes.HTTP_404_NOT_FOUND
        product = Products.query.filter_by(id=id).first()
        if not product:
            return jsonify({"message": "Product not found"}), http_status_codes.HTTP_404_NOT_FOUND
        return jsonify({"message": "Product retrieved successfully", "product": product.to_dict()}), http_status_codes.HTTP_200_OK
    except Exception as e:
        return jsonify({'error': str(e)}), http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR
    
    
    
    

@auth.get("/search")
def search():
    query = request.args.get("query", "")
    per_page = 10  # Fixed number of items per page

    # Fetch products that match the query across multiple fields
    search_term = f"%{query}%"
    products_query = Products.query.filter(
        db.or_(
            Products.name.ilike(search_term),
            Products.description.ilike(search_term),
            Products.model.ilike(search_term),
            Products.color.ilike(search_term),
            db.or_(*[getattr(Products, f'specification_{i}').ilike(search_term) 
                    for i in range(1, 16)])  # Search all 15 specification fields
        )
    )

    # Get total count to determine if pagination is needed
    total_products = products_query.count()

    # If no products or few products, return all without pagination
    if total_products <= per_page:
        products = products_query.all()
        response = {
            "products": [product.to_dict() for product in products],  # Use to_dict() for full specs
            "message": f"{total_products} product(s) found" if total_products > 0 else f"No products found matching '{query}'"
        }
        return jsonify(response), http_status_codes.HTTP_200_OK

    # Paginate products if more than per_page
    products_paginated = products_query.paginate(page=1, per_page=per_page, error_out=False)

    response = {
        "products": [product.to_dict() for product in products_paginated.items],  # Full specs
        "pagination": {
            "current_page": products_paginated.page,
            "total_pages": products_paginated.pages,
            "has_next": products_paginated.has_next,
            "has_prev": products_paginated.has_prev,
            "next_page": (
                products_paginated.next_num if products_paginated.has_next else None
            ),
            "prev_page": (
                products_paginated.prev_num if products_paginated.has_prev else None
            ),
        },
    }

    return jsonify(response), http_status_codes.HTTP_200_OK





@auth.post("/filter-products")
def filter_products():
    # Get the JSON body from the request
    filters = request.get_json() or {}
    
    # Extract filter parameters (all optional)
    name = filters.get("name")
    model = filters.get("model")
    color = filters.get("color")
    price = filters.get("price")  # Must be a dict with min and/or max

    # Start with base query
    products_query = Products.query

    # Apply filters dynamically based on what's provided
    if name:
        products_query = products_query.filter(Products.name.ilike(f"%{name}%"))
    if model:
        products_query = products_query.filter(Products.model.ilike(f"%{model}%"))
    if color:
        products_query = products_query.filter(Products.color.ilike(f"%{color}%"))
    if price:
        if not isinstance(price, dict):
            return jsonify({"error": "Price must be an object with 'min' and/or 'max'"}), http_status_codes.HTTP_400_BAD_REQUEST
        
        min_price = price.get("min")
        max_price = price.get("max")
        
        if min_price is not None:
            products_query = products_query.filter(Products.price >= float(min_price))
        if max_price is not None:
            products_query = products_query.filter(Products.price <= float(max_price))

    # Execute the query
    products = products_query.all()
    total_products = len(products)

    # Prepare response
    if total_products == 0:
        response = {
            "products": [],
            "message": "No products found matching the provided filters"
        }
    else:
        response = {
            "products": [product.to_dict() for product in products],  # Full details with all specs
            "message": f"{total_products} product(s) found"
        }

    return jsonify(response), http_status_codes.HTTP_200_OK




# Get all gadgets

@auth.get("/all_gadgets/<string:id>")
def all_gadgets(id):
    try:
        category = Category.query.get(id)
        if not category:
            return jsonify({'error': 'Category not found'}), http_status_codes.HTTP_404_NOT_FOUND
            
        gadgets = Products.query.filter_by(category_id=id).order_by(Products.created_at.desc()).all()
        
        if not gadgets:
            return jsonify({
                'message': 'No gadgets found in this category',
                'gadgets': []
            }), 200
            
        gadgets_list = [gadget.to_dict() for gadget in gadgets]
        
        return jsonify({
            'message': 'Gadgets retrieved successfully',
            'gadgets': gadgets_list,
            "image": gadgets.image,
        }), http_status_codes.HTTP_200_OK
        
    except Exception as e:
        return jsonify({'error': str(e)}), http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR
    
    
    
# Get all toys

@auth.get("/all_toys/<string:id>")
def all_toys(id):
    try:
        category = Category.query.get(id)
        if not category:
            return jsonify({'error': 'Category not found'}), http_status_codes.HTTP_404_NOT_FOUND
            
        # toys = Products.query.filter_by(category_id=id).all()
        toys = Products.query.filter_by(category_id=id).order_by(Products.created_at.desc()).all()
        
        
        if not toys:
            return jsonify({
                'message': 'No toys found in this category',
                'toys': []
            }), 200
            
        toys_list = [toy.to_dict() for toy in toys]
        
        return jsonify({
            'message': 'Toys retrieved successfully',
            'toys': toys_list,
            "image": toys.image,
        }), http_status_codes.HTTP_200_OK
        
    except Exception as e:
        return jsonify({'error': str(e)}), http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR
    
    
    
    
    
# Get all beds
@auth.get("/all_beds/<string:id>")  
def all_beds(id):
    try:
        category = Category.query.get(id)
        if not category:
            return jsonify({'error': 'Category not found'}), http_status_codes.HTTP_404_NOT_FOUND
            
        # beds = Products.query.filter_by(category_id=id).all()
        beds = Products.query.filter_by(category_id=id).order_by(Products.created_at.desc()).all()
        
        
        if not beds:
            return jsonify({
                'message': 'No beds found in this category',
                'beds': []
            }), 200
            
        beds_list = [bed.to_dict() for bed in beds]
        
        return jsonify({
            'message': 'Beds retrieved successfully',
            'beds': beds_list,
            "image": beds.image,
        }), http_status_codes.HTTP_200_OK
        
    except Exception as e:
        return jsonify({'error': str(e)}), http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR
    


# Get all categories
@auth.get('/all_categories')
def all_categories():
    try:
        categories = Category.query.all()
        
        if not categories:
            return jsonify({
                'message': 'No categories found',
                'categories': []}), http_status_codes.HTTP_404_NOT_FOUND
            
        categories_list = [category.to_dict() for category in categories]
        
        return jsonify({
            'message': 'Categories retrieved successfully',
            'categories': categories_list
        }), http_status_codes.HTTP_200_OK
        
    except Exception as e:
        return jsonify({'error': str(e)}), http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR
            