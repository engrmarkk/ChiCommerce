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
    request,
    Blueprint,
    jsonify,
)
from flask_jwt_extended import (
    jwt_required,
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
from src.constants.env_constant import EXCEPTION_MESSAGE
from src.constants.status_message import StatusMessage
from src.decorators import admin_required
from src.func import (
    update_product_specifications,
    update_product_images,
    get_all_orders,
)
from src.logger import logger
from src.model.database import (
    db,
    Category,
    Products,
    Cart,
    Specification,
    ProductImages,
    User, Order, ProductPurchased
)
from src.utils.util import return_response, data_cache
import json

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

        # Validate required fields
        if not name:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Category name is required",
            )

        if not image:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Category image is required",
            )

        # Check for duplicate category name
        existing_category = Category.query.filter_by(name=name).first()

        if existing_category:
            return return_response(
                http_status_codes.HTTP_409_CONFLICT,
                status=StatusMessage.FAILED,
                message="This category name already exists",
            )

        # Create new category
        new_category = Category(name=name, image=image)

        db.session.add(new_category)
        db.session.commit()

        return return_response(
            http_status_codes.HTTP_201_CREATED,
            status=StatusMessage.SUCCESS,
            message="New category added successfully",
            category=new_category.to_dict(),
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


@admin.delete("/delete_category/<string:category_id>")
@jwt_required()
@admin_required()
def delete_category(category_id):
    category = Category.query.get(category_id)
    if not category:
        return return_response(
            http_status_codes.HTTP_404_NOT_FOUND,
            status=StatusMessage.FAILED,
            message="Category not found",
        )

    try:
        products = Products.query.filter_by(category_id=category_id).all()

        if products:
            get_red = redis_conn.get(category_id)
            if get_red:
                pass
            else:
                redis_conn.set(category_id, 1, expire=10)
                return return_response(
                    http_status_codes.HTTP_409_CONFLICT,
                    status=StatusMessage.FAILED,
                    message="Deleting this category will delete the products under it, click the button again if you want to proceed",
                )

        for product in products:
            # First clean up dependent carts
            carts = Cart.query.filter_by(product_id=product.id).all()
            for cart in carts:
                db.session.delete(cart)

            db.session.delete(product)

        db.session.delete(category)
        db.session.commit()

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Category, products, and linked carts deleted successfully",
        )

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# Update Categories
@admin.put("/update_category/<string:id>")
@jwt_required()
@admin_required()
def update_category(id):

    category = Category.query.get(id)

    if not category:
        return return_response(
            http_status_codes.HTTP_404_NOT_FOUND,
            status=StatusMessage.FAILED,
            message="Category not found",
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
        return return_response(
            http_status_codes.HTTP_409_CONFLICT,
            status=StatusMessage.FAILED,
            message="This category name already exists",
        )

    try:
        # Update the category name
        category.name = new_cat
        category.image = new_image
        db.session.commit()

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Category updated successfully",
            category=category.to_dict(),
        )

    except SQLAlchemyError as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
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
        description = data.get("description")
        specifications = data.get("specifications", [])
        product_images = data.get("product_images", [])

        existing_product = Products.query.filter(
            Products.name.ilike(name),
            Products.category_id == category_id,
        ).first()
        if existing_product:
            return return_response(
                http_status_codes.HTTP_409_CONFLICT,
                status=StatusMessage.FAILED,
                message="Product already exists",
            )

        if not all([name, price, color, model, category_id, image, description]):
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Missing required fields",
            )

        category = Category.query.get(category_id)
        if not category:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Invalid category_id",
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
            specification=[
                Specification(
                    name=spec.get("name"), description=spec.get("description")
                )
                for spec in specifications
            ],
            product_images=[ProductImages(image=image) for image in product_images],
        )

        db.session.add(new_product)
        db.session.commit()

        redis_conn.clear_partial_cache(f"admin_products:all_products:")

        return return_response(
            http_status_codes.HTTP_201_CREATED,
            status=StatusMessage.SUCCESS,
            message="Product added successfully",
            product=new_product.to_dict(),
        )

    except ValueError:
        return return_response(
            http_status_codes.HTTP_400_BAD_REQUEST,
            status=StatusMessage.FAILED,
            message="Invalid price format",
        )
    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


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
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="Product not found",
            )

        # Delete the product
        db.session.delete(product)
        db.session.commit()

        redis_conn.clear_partial_cache(f"admin_products:all_products:")
        redis_conn.delete(f"admin_products:single_product:{id}")
    
        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Product deleted successfully",
        )

    except IntegrityError as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_409_CONFLICT,
            status=StatusMessage.FAILED,
            message="Product has active orders and cannot be deleted",
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
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
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="Product not found",
            )

        # Get the request data
        data = request.json

        # Update only the fields that are provided in the request, keeping existing values otherwise
        product.name = data.get("name") or product.name
        product.price = data.get("price") or product.price
        product.color = data.get("color") or product.color
        product.model = data.get("model") or product.model
        product.image = data.get("image") or product.image
        product.category_id = data.get("category_id") or product.category_id
        product.description = data.get("description") or product.description
        product.out_of_stock = data.get("out_of_stock", product.out_of_stock)

        if data.get("specifications"):
            update_product_specifications(id, data.get("specifications", []))

        if data.get("product_images"):
            update_product_images(id, data.get("product_images", []))

        db.session.commit()

        redis_conn.delete(f"admin_products:single_product:{id}")
        redis_conn.clear_partial_cache(f"admin_products:all_products:")

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Product updated successfully",
            product=product.to_dict(),
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# View single product
@admin.get("/single_product/<string:id>")
@jwt_required()
@admin_required()
def single_product(id):
    try:
        key = f"admin_products:single_product:{id}"
        cached_product = redis_conn.get(key)
        if cached_product:
            return return_response(
                http_status_codes.HTTP_200_OK,
                status=StatusMessage.SUCCESS,
                message="Product retrieved successfully",
                product=json.loads(cached_product)
            )
        # Query the product by its ID
        product = Products.query.get(id)

        # Check if the product exists
        if not product:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="Product not found",
            )

        redis_conn.set(f"admin_products:single_product:{id}", json.dumps(product.to_dict(all_products=True)), expire=6000)

        # Return the product details
        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Product retrieved successfully",
            product=product.to_dict(all_products=True),
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# Get all categories
@admin.get("/all_categories")
@jwt_required()
@admin_required()
def get_all_categories():
    try:
        data_res = data_cache(
            f"products:all_categories",
            {},
            6000,
        )
        if data_res:
            return return_response(
                http_status_codes.HTTP_200_OK,
                status=StatusMessage.SUCCESS,
                message="Categories retrieved successfully",
                **{"categories": data_res},
            )

        categories = Category.query.order_by(Category.name.asc()).all()
        res_data = data_cache(
            f"products:all_categories",
            [category.to_dict() for category in categories],
            6000,
        )
        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Categories retrieved successfully",
            **{"categories": res_data},
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


@admin.get("/product_by_category/<string:category_id>")
@jwt_required()
@admin_required()
def get_product_by_category(category_id):
    try:
        data_res = data_cache(
            f"products:product_by_category:{category_id}",
            {},
            6000,
        )
        if data_res:
            return return_response(
                http_status_codes.HTTP_200_OK,
                status=StatusMessage.SUCCESS,
                message="Products retrieved successfully",
                **{"gadgets": data_res},
            )

        category = Category.query.get(category_id)
        if not category:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="Category not found",
            )

        gadgets = Products.query.filter_by(category_id=category_id).all()

        if not gadgets:
            return return_response(
                http_status_codes.HTTP_200_OK,
                status=StatusMessage.SUCCESS,
                message="No gadgets found in this category",
                **{"gadgets": []},
            )

        gadgets_list = [gadget.to_dict() for gadget in gadgets]

        res_data = data_cache(
            f"products:product_by_category:{category_id}",
            gadgets_list,
            6000,
        )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Gadgets retrieved successfully",
            **{"gadgets": res_data},
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
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

        data_res = data_cache(
            f"admin_products:all_products:{query}:{page}:{per_page}",
            {},
            6000,
        )
        if data_res:
            return return_response(
                http_status_codes.HTTP_200_OK,
                status=StatusMessage.SUCCESS,
                message="Products retrieved successfully",
                **data_res,
            )

        products_query = Products.query.filter(
            Products.name.ilike(f"%{query}%")
        ).order_by(Products.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

        total_pages = products_query.pages
        has_next = products_query.has_next
        has_prev = products_query.has_prev

        res_data = data_cache(
            f"admin_products:all_products:{query}:{page}:{per_page}",
            {
                "products": [product.to_dict() for product in products_query.items],
                "total_pages": total_pages,
                "total_items": products_query.total,
                "page": page,
                "per_page": per_page,
                "has_next": has_next,
                "has_prev": has_prev,
            },
            6000,
        )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Products retrieved successfully",
            **res_data,
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# get all orders
@admin.get("/all_orders")
# @jwt_required()
# @admin_required()
def all_orders():
    try:
        query = request.args.get("query", "")
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 10))

        data_res = data_cache(
            f"admin_all_orders:{query}:{page}:{per_page}",
            {},
            60,
        )
        if data_res:
            return return_response(
                http_status_codes.HTTP_200_OK,
                status=StatusMessage.SUCCESS,
                message="Orders retrieved successfully",
                **data_res,
            )

        res = get_all_orders(query, page, per_page)

        # save to cache
        data_res = data_cache(
            f"admin_all_orders:{query}:{page}:{per_page}",
            res,
            60,
        )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Orders retrieved successfully",
            **data_res,
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )

# get users
@admin.get("/get_users")
@jwt_required()
@admin_required()
def get_users():
    try:
        query = request.args.get("query", "")
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 10))

        res_data = data_cache(
            f"admin_users:get_users:{query}:{page}:{per_page}",
            {},
            6000,
        )
        if res_data:
            return return_response(
                http_status_codes.HTTP_200_OK,
                status=StatusMessage.SUCCESS,
                message="Users retrieved successfully",
                **res_data,
            )

        users_query = User.query.filter(
            User.email.ilike(f"%{query}%")
        ).order_by(User.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

        total_pages = users_query.pages
        has_next = users_query.has_next
        has_prev = users_query.has_prev

        res_data = data_cache(
            f"admin_users:get_users:{query}:{page}:{per_page}",
            {
                "users": [user.to_dict() for user in users_query.items],
                "total_pages": total_pages,
                "total_items": users_query.total,
                "page": page,
                "per_page": per_page,
                "has_next": has_next,
                "has_prev": has_prev,
            },
            6000,
        )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Users retrieved successfully",
            **res_data,
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# get one user with the product purchased and orders
@admin.get("/get_user/<user_id>")
@jwt_required()
@admin_required()
def get_user(user_id):
    try:
        data_res = data_cache(
            f"admin_users:get_user:{user_id}",
            {},
            6000,
        )
        if data_res:
            return return_response(
                http_status_codes.HTTP_200_OK,
                status=StatusMessage.SUCCESS,
                message="User retrieved successfully",
                **data_res,
            )

        user = User.query.get(user_id)
        if not user:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="User not found",
            )

        orders = Order.query.filter_by(user_id=user.id
                                       ).order_by(Order.created_at.desc()).all()

        res_data = {
            "user": user.to_dict(),
            "orders": [order.admin_to_dict() for order in orders],
        }

        data_cache(
            f"admin_users:get_user:{user_id}",
            res_data,
            6000,
        )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="User retrieved successfully",
            **res_data,
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# get purchased product by order id
@admin.get("/get_order/<order_id>")
@jwt_required()
@admin_required()
def get_order(order_id):
    try:
        data_res = data_cache(
            f"admin_orders:get_order:{order_id}",
            {},
            6000,
        )
        if data_res:
            return return_response(
                http_status_codes.HTTP_200_OK,
                status=StatusMessage.SUCCESS,
                message="Order retrieved successfully",
                **data_res,
            )

        order = Order.query.get(order_id)
        if not order:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="Order not found",
            )

        res_data = order.admin_to_dict(get_all=True)

        data_cache(
            f"admin_orders:get_order:{order_id}",
            res_data,
            6000,
        )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Order retrieved successfully",
            **res_data,
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )
