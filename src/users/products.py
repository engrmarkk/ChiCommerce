import cloudinary
import cloudinary.uploader
import datetime
import random
import re
import string
import traceback
import validators
from datetime import timedelta
from dotenv import load_dotenv
from flask import (
    request,
    session,
    Blueprint,
    jsonify,
)
from flask_jwt_extended import (
    jwt_required,
    current_user,
)

import src.cloudinary_config
from src.constants import http_status_codes
from src.logger import logger
from src.model.database import db, User, Products, Category, Cart
from src.utils.util import return_response
from src.constants.status_message import StatusMessage
from src.constants.env_constant import EXCEPTION_MESSAGE

# from src.services.mail import send_mail


products = Blueprint("products", __name__, url_prefix="/products")


# Get all products paginated
@products.get("/get_all_products")
# @jwt_required()
def get_all_products():
    try:
        query = request.args.get("query", "")
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 10))

        products_query = (
            Products.query.filter(Products.name.ilike(f"%{query}%") if query else True)
            .order_by(Products.created_at.desc())
            .paginate(page=page, per_page=per_page, error_out=False)
        )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Products retrieved successfully",
            **{
                "products": [product.to_dict() for product in products_query.items],
                "total_pages": products_query.pages,
                "total_items": products_query.total,
                "page": page,
                "per_page": per_page,
                "has_next": products_query.has_next,
                "has_prev": products_query.has_prev,
            },
        )

    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# Get single product
@products.get("/single_product/<string:id>")
# @jwt_required()
def get_single_product(id):
    try:
        # if not current_user:
        #     return jsonify({"message": "User not found"}), http_status_codes.HTTP_404_NOT_FOUND
        product = Products.query.filter_by(id=id).first()
        if not product:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="Product not found",
            )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Product retrieved successfully",
            product=product.to_dict(),
        )

    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


@products.get("/search")
def search():
    try:
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
                db.or_(
                    *[
                        getattr(Products, f"specification_{i}").ilike(search_term)
                        for i in range(1, 16)
                    ]
                ),  # Search all 15 specification fields
            )
        )

        # Get total count to determine if pagination is needed
        total_products = products_query.count()

        # If no products or few products, return all without pagination
        if total_products <= per_page:
            products = products_query.all()
            response = {
                "products": [
                    product.to_dict() for product in products
                ],  # Use to_dict() for full specs
                "message": (
                    f"{total_products} product(s) found"
                    if total_products > 0
                    else f"No products found matching '{query}'"
                ),
            }
            return jsonify(response), http_status_codes.HTTP_200_OK

        # Paginate products if more than per_page
        products_paginated = products_query.paginate(
            page=1, per_page=per_page, error_out=False
        )

        response = {
            "products": [product.to_dict() for product in products_paginated.items],
            "page": products_paginated.page,
            "total_pages": products_paginated.pages,
            "total_items": products_paginated.total,
            "has_next": products_paginated.has_next,
            "has_prev": products_paginated.has_prev,
            "next_page": (
                products_paginated.next_num if products_paginated.has_next else None
            ),
            "prev_page": (
                products_paginated.prev_num if products_paginated.has_prev else None
            ),
        }

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Products retrieved successfully",
            **response,
        )
    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


@products.post("/filter-products")
def filter_products():
    try:
        # Get the JSON body from the request
        filters = request.get_json() or {}

        # Extract filter parameters (all optional)
        name = filters.get("name")
        model = filters.get("model")
        color = filters.get("color")
        min_price = filters.get("min_price")
        max_price = filters.get("max_price")

        # Start with base query
        products_query = Products.query

        # Apply filters dynamically based on what's provided
        if name:
            products_query = products_query.filter(Products.name.ilike(f"%{name}%"))
        if model:
            products_query = products_query.filter(Products.model.ilike(f"%{model}%"))
        if color:
            products_query = products_query.filter(Products.color.ilike(f"%{color}%"))

        if min_price:
            products_query = products_query.filter(
                Products.price >= float(min_price)
            )
        if max_price:
            products_query = products_query.filter(
                Products.price <= float(max_price)
            )

        # Execute the query
        products = products_query.all()
        total_products = len(products)

        # Prepare response
        if total_products == 0:
            response = {
                "products": [],
                "message": "No products found matching the provided filters",
            }
        else:
            response = {
                "products": [
                    product.to_dict() for product in products
                ],  # Full details with all specs
                "message": f"{total_products} product(s) found",
            }

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Products retrieved successfully",
            **response,
        )

    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# Get all gadgets
@products.get("/product_by_category/<string:category_id>")
def product_by_category(category_id):
    try:
        category = Category.query.get(category_id)
        if not category:
            return (
                jsonify({"message": "Category not found"}),
                http_status_codes.HTTP_404_NOT_FOUND,
            )

        products = (
            Products.query.filter_by(category_id=category_id)
            .order_by(Products.created_at.desc())
            .all()
        )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Products retrieved successfully",
            gadgets=[gadget.to_dict() for gadget in products],
        )

    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# Get all categories
@products.get("/all_categories")
def all_categories():
    try:
        categories = Category.query.all()

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Categories retrieved successfully",
            categories=[category.to_dict() for category in categories],
        )

    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# Users adding items to cart
@products.post("/add_to_cart")
@jwt_required()
def add_to_cart():
    try:
        data = request.get_json()
        product_id = data.get("product_id")
        quantity = data.get("quantity")

        if not product_id or not quantity:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Product and quantity are required",
            )

        # Check if the product exists
        product = Products.query.get(product_id)
        if not product:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="Product not found",
            )

        # Check if the product is available
        if product.out_of_stock:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Product is not available",
            )

        # Add the product to the cart
        cart = Cart(user_id=current_user.id, product_id=product_id, quantity=quantity)
        db.session.add(cart)
        db.session.commit()

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Product added to cart successfully",
            product=product.to_dict(),
        )

    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# Get all items in cart
@products.get("/get_all_cart_items")
@jwt_required()
def get_all_cart_items():
    try:
        cart_items = Cart.query.filter_by(user_id=current_user.id).all()
        if not cart_items:
            return return_response(
                http_status_codes.HTTP_200_OK,
                status=StatusMessage.SUCCESS,
                message="Your cart is empty",
                cart_items=[],
            )

        consolidated_items = {}
        for item in cart_items:
            if item.product_id in consolidated_items:
                consolidated_items[item.product_id]["quantity"] += item.quantity
            else:
                consolidated_items[item.product_id] = item.to_dict()

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Cart items retrieved successfully",
            cart_items=list(consolidated_items.values()),
        )

    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# Update cart items
@products.put("/update_cart")
@jwt_required()
def update_cart():
    try:
        data = request.get_json()
        item_id = data.get("item_id")
        quantity = data.get("quantity")

        if not item_id or quantity is None:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Item ID and quantity are required",
            )

        cart_item = Cart.query.filter_by(id=item_id, user_id=current_user.id).first()

        if not cart_item:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="Cart item not found",
            )

        # Update the quantity
        cart_item.quantity = quantity
        db.session.commit()

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Cart item updated successfully",
            cart_item=cart_item.to_dict(),
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# Remove item from cart
@products.delete("/remove_from_cart/<string:item_id>")
@jwt_required()
def remove_from_cart(item_id):
    try:
        cart_item = Cart.query.filter_by(id=item_id, user_id=current_user.id).first()

        if not cart_item:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="Cart item not found",
            )

        db.session.delete(cart_item)
        db.session.commit()

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message=f" Item removed successfully",
        )

    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )
