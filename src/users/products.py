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

        return (
            jsonify(
                {
                    "message": "Products retrieved successfully",
                    "products": [product.to_dict() for product in products_query.items],
                    "total_pages": products_query.pages,
                    "total_items": products_query.total,
                    "page": page,
                    "per_page": per_page,
                    "has_next": products_query.has_next,
                    "has_prev": products_query.has_prev,
                }
            ),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Error retrieving products: {str(e)}")
        return (
            jsonify({"message": "Network Error"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
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
            return (
                jsonify({"message": "Product not found"}),
                http_status_codes.HTTP_404_NOT_FOUND,
            )
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
        logger.error(f"Error retrieving product: {str(e)}")
        return (
            jsonify({"message": "Network Error"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


@products.get("/search")
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
        "products": [
            product.to_dict() for product in products_paginated.items
        ],  # Full specs
        "pagination": {
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
        },
    }

    return jsonify(response), http_status_codes.HTTP_200_OK


@products.post("/filter-products")
def filter_products():
    try:
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
                return (
                    jsonify(
                        {"message": "Price must be an object with 'min' and/or 'max'"}
                    ),
                    http_status_codes.HTTP_400_BAD_REQUEST,
                )

            min_price = price.get("min")
            max_price = price.get("max")

            if min_price is not None:
                products_query = products_query.filter(
                    Products.price >= float(min_price)
                )
            if max_price is not None:
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

        return jsonify(response), http_status_codes.HTTP_200_OK

    except Exception as e:
        logger.error(f"filter products error: {str(e)}")
        return (
            jsonify({"message": "Network Error"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
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

        return (
            jsonify(
                {
                    "message": "Products retrieved successfully",
                    "gadgets": [gadget.to_dict() for gadget in products],
                    # "image": gadgets.image,
                }
            ),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"product_by_category error: {str(e)}")
        return (
            jsonify({"message": "Network Error"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# Get all categories
@products.get("/all_categories")
def all_categories():
    try:
        categories = Category.query.all()

        return (
            jsonify(
                {
                    "message": "Categories retrieved successfully",
                    "categories": [category.to_dict() for category in categories],
                }
            ),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        return (
            jsonify({"message": "Network Error"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
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
            return (
                jsonify({"message": "Product and quantity are required"}),
                http_status_codes.HTTP_400_BAD_REQUEST,
            )

        # Check if the product exists
        product = Products.query.get(product_id)
        if not product:
            return (
                jsonify({"message": "Product not found"}),
                http_status_codes.HTTP_404_NOT_FOUND,
            )

        # Check if the product is available
        if product.out_of_stock:
            return (
                jsonify({"message": "Product is not available"}),
                http_status_codes.HTTP_400_BAD_REQUEST,
            )

        # Add the product to the cart
        cart = Cart(user_id=current_user.id, product_id=product_id, quantity=quantity)
        db.session.add(cart)
        db.session.commit()

        return (
            jsonify(
                {
                    "message": "Product added to cart successfully",
                    "product": product.to_dict(),
                }
            ),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Error adding product to cart: {str(e)}")
        return (
            jsonify({"message": "Network Error"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# Get all items in cart
@products.get("/get_all_cart_items")
@jwt_required()
def get_all_cart_items():
    try:
        cart_items = Cart.query.filter_by(user_id=current_user.id).all()
        if not cart_items:
            return (
                jsonify({"message": "Your cart is empty", "cart_items": []}),
                http_status_codes.HTTP_200_OK,
            )

        consolidated_items = {}
        for item in cart_items:
            if item.product_id in consolidated_items:
                consolidated_items[item.product_id]["quantity"] += item.quantity
            else:
                consolidated_items[item.product_id] = item.to_dict()

        return (
            jsonify({"cart_items": list(consolidated_items.values())}),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        logger.error(f"Error getting cart items: {str(e)}")
        return (
            jsonify({"message": "Network Error"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
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
            return (
                jsonify({"message": "Item ID and quantity are required"}),
                http_status_codes.HTTP_400_BAD_REQUEST,
            )

        cart_item = Cart.query.filter_by(id=item_id, user_id=current_user.id).first()

        if not cart_item:
            return (
                jsonify({"message": "Cart item not found"}),
                http_status_codes.HTTP_404_NOT_FOUND,
            )

        # Update the quantity
        cart_item.quantity = quantity
        db.session.commit()

        return (
            jsonify(
                {
                    "message": "Cart item updated successfully",
                    "cart_item": cart_item.to_dict(),
                }
            ),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating cart item: {str(e)}")
        return (
            jsonify({"message": "Network Error"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# Remove item from cart
@products.delete("/remove_from_cart/<string:item_id>")
@jwt_required()
def remove_from_cart(item_id):
    try:
        cart_item = Cart.query.filter_by(id=item_id, user_id=current_user.id).first()

        if not cart_item:
            return (
                jsonify({"message": "Cart item not found"}),
                http_status_codes.HTTP_404_NOT_FOUND,
            )

        db.session.delete(cart_item)
        db.session.commit()

        return (
            jsonify({"message": f" Item removed successfully"}),
            http_status_codes.HTTP_200_OK,
        )

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error removing cart item: {str(e)}")
        return (
            jsonify({"message": "Network Error"}),
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
        )
