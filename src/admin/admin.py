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
from http import HTTPStatus
from itsdangerous import URLSafeTimedSerializer, BadSignature
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.exc import SQLAlchemyError
from urllib.parse import quote
from urllib.parse import unquote
from werkzeug.security import generate_password_hash, check_password_hash

from src.connections.redis_connection import redis_conn
from src.constants import http_status_codes
from src.decorators import admin_required
from src.extentions.extensions import jwt, mail, cors  # Ensure this import is correct
from src.logger import logger
from src.model.database import db, User, Category, Products, Cart
from src.utils import validate_password

# Blueprint setup
admin = Blueprint("admin", __name__, url_prefix="/admin")

# Cloudinary Config
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
)


@admin.post("/add_category")
@jwt_required()
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

        # Create new category
        new_category = Category(name=name, image=image)

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


@admin.delete("/delete_category/<string:category_id>")
@jwt_required()
@admin_required()
def delete_category(category_id):
    category = Category.query.get(category_id)
    if not category:
        return (
            jsonify({"message": "Category not found"}),
            http_status_codes.HTTP_404_NOT_FOUND,
        )

    try:
        products = Products.query.filter_by(category_id=category_id).all()

        if products:
            get_red = redis_conn.get(category_id)
            if get_red:
                pass
            else:
                redis_conn.set(category_id, 1, expire=10)
                return (
                    jsonify(
                        {"message": "Deleting this category will delete the products under it, click the button again if you want to proceed"}
                    ),
                    http_status_codes.HTTP_409_CONFLICT,
                )

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
@jwt_required()
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
@jwt_required()
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
        description = (data.get("description"))

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

        new_product = Products(
            name=name,
            price=float(price),
            color=color,
            model=model,
            image=image,
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
@jwt_required()
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
@jwt_required()
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
@jwt_required()
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


# Get all categories
@admin.get("/all_categories")
@jwt_required()
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
@jwt_required()
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
@jwt_required()
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
