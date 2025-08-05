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
    get_jwt_identity,
    verify_jwt_in_request,
)
from sqlalchemy import or_

import src.cloudinary_config
from src.constants import http_status_codes
from src.logger import logger
from src.model.database import (
    db,
    User,
    Products,
    Category,
    Cart,
    Specification,
    Favorite,
    Order
)
from src.func import (
    finalize_cart_item,
    get_cart_items_by_ref_id,
    get_address,
    create_order,
    get_order_address,
    add_order_address
)
from src.utils.util import return_response, data_cache, format_datetime
from src.constants.status_message import StatusMessage
from src.constants.env_constant import EXCEPTION_MESSAGE

# from src.services.mail import send_mail


products = Blueprint("products", __name__, url_prefix="/products")


def get_user_id():
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
    except Exception:
        user_id = None

    return user_id


# Get all products paginated
@products.get("/get_all_products")
# @jwt_required()
def get_all_products():
    try:
        user_id = get_user_id()
        filters = request.args
        page = int(filters.get("page", 1))
        per_page = int(filters.get("per_page", 10))
        name = filters.get("name", "")
        model = filters.get("model", "")
        color = filters.get("color", "")
        min_price = filters.get("min_price", "")
        max_price = filters.get("max_price", "")
        category_id = filters.get("category_id", "")
        sort_by = filters.get("sort_by", "created_at")
        sort_order = filters.get("sort_order", "desc")

        products_query = (
            Products.query.filter(
                Products.model.ilike(f"%{model}%") if model else True,
                Products.color.ilike(f"%{color}%") if color else True,
                Products.price >= float(min_price) if min_price else True,
                Products.price <= float(max_price) if max_price else True,
                Products.name.ilike(f"%{name}%") if name else True,
                Products.category_id == category_id if category_id else True,
            )
            .order_by(
                getattr(Products, sort_by).desc()
                if sort_order == "desc"
                else getattr(Products, sort_by).asc()
            )
            .paginate(page=page, per_page=per_page, error_out=False)
        )

        res_data = data_cache(
            f"products:all:{page}:{per_page}:{name}:{model}:{color}:{min_price}:{max_price}:{category_id}:{sort_by}:{sort_order}",
            {
                "products": [
                    product.to_dict(user_id=user_id) for product in products_query.items
                ],
                "total_pages": products_query.pages,
                "total_items": products_query.total,
                "page": page,
                "per_page": per_page,
                "has_next": products_query.has_next,
                "has_prev": products_query.has_prev,
            },
            60,
        )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Products retrieved successfully",
            **res_data,
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
        user_id = get_user_id()
        # if not current_user:
        #     return jsonify({"message": "User not found"}), http_status_codes.HTTP_404_NOT_FOUND
        product = Products.query.filter_by(id=id).first()
        if not product:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="Product not found",
            )

        res_data = data_cache(
            f"products:single:{id}",
            product.to_dict(all_products=True, user_id=user_id),
            60,
        )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Product retrieved successfully",
            **{"product": res_data},
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

        # Fetch products that match the query across multiple fields, including Specification
        search_term = f"%{query}%"
        # Subquery to find product_ids with matching specifications
        matching_spec_product_ids = (
            db.session.query(Specification.product_id)
            .filter(
                or_(
                    Specification.name.ilike(search_term),
                    Specification.description.ilike(search_term),
                )
            )
            .subquery()
        )

        products_query = Products.query.join(
            Category, Products.category_id == Category.id
        ).filter(
            or_(
                Products.name.ilike(search_term),
                Products.description.ilike(search_term),
                Products.model.ilike(search_term),
                Products.color.ilike(search_term),
                Products.id.in_(matching_spec_product_ids.select()),
                Category.name.ilike(f"%{query}%") if query else True,
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

        res_data = data_cache(f"products:search:{query}:{per_page}", response, 60)

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Products retrieved successfully",
            **res_data,
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
            products_query = products_query.filter(Products.price >= float(min_price))
        if max_price:
            products_query = products_query.filter(Products.price <= float(max_price))

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


# Get all categories
@products.get("/all_categories")
def all_categories():
    try:
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
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


@products.get("/related_products/<string:id>")
def related_products(id):
    try:
        # Find the main product
        product = Products.query.filter_by(id=id).first()
        if not product:
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="Product not found",
            )
        # Query for up to 10 other products in the same category, excluding the current product
        related = (
            Products.query.filter(
                Products.category_id == product.category_id, Products.id != product.id
            )
            .order_by(Products.created_at.desc())
            .limit(10)
            .all()
        )

        res_data = data_cache(
            f"products:related:{id}", [p.to_dict() for p in related], 60
        )
        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Related products retrieved successfully",
            **{"related_products": res_data},
        )

    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# favotite and unfavorite a product
@products.post("/favorite")
@jwt_required()
def favorite():
    try:
        data = request.get_json()
        product_id = data.get("product_id")

        if not product_id:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Product ID is required",
            )

        if not Products.query.filter_by(id=product_id).first():
            return return_response(
                http_status_codes.HTTP_404_NOT_FOUND,
                status=StatusMessage.FAILED,
                message="Product not found",
            )

        favorite = Favorite.query.filter_by(
            user_id=current_user.id, product_id=product_id
        ).first()
        if favorite:
            db.session.delete(favorite)
            db.session.commit()
            return return_response(
                http_status_codes.HTTP_200_OK,
                status=StatusMessage.SUCCESS,
                message="Product unfavorited successfully",
            )

        favorite = Favorite(user_id=current_user.id, product_id=product_id)
        db.session.add(favorite)
        db.session.commit()
        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Product favorited successfully",
        )
    except Exception as e:
        db.session.rollback()
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# get favorited products (desc order)
@products.get("/get_favorites")
@jwt_required()
def get_favorites():
    try:
        favorites = (
            Favorite.query.filter_by(user_id=current_user.id)
            .order_by(Favorite.created_at.desc())
            .all()
        )
        res_data = data_cache(
            f"products:favorites:{current_user.id}",
            [f.to_dict() for f in favorites],
            60,
        )
        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Favorites retrieved successfully",
            **{"favorites": res_data},
        )
    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# get trending products, the latest 8 products added
@products.get("/get_trending")
def get_trending():
    try:
        products = Products.query.order_by(Products.created_at.desc()).limit(8).all()
        res_data = data_cache(f"products:trending", [p.to_dict() for p in products], 60)
        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Trending products retrieved successfully",
            **{"trending": res_data},
        )
    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# add to cart and return cart items with total price
@products.post("/finalize_cart")
@jwt_required()
def finalize_cart():
    try:
        data = request.get_json()
        products = data.get("products", [])
        if not products:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="No products provided",
            )

        cart_items = finalize_cart_item(products, current_user.id)

        # delivery fee
        delivery_fee = 2000
        cart_ref_id = cart_items[0]["cart_ref_id"] if cart_items else None

        total_price = sum(item["amount"] for item in cart_items) + delivery_fee

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Cart finalized successfully",
            **{
                "cart_items": cart_items,
                "total_price": total_price,
                "delivery_fee": delivery_fee,
                "cart_ref_id": cart_ref_id,
                "user_email": current_user.email,
            },
        )
    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# get finalized carts
@products.get("/get_finalized_carts/<cart_ref_id>")
@jwt_required()
def get_finalized_carts(cart_ref_id):
    try:
        user_id = current_user.id
        cart_items = get_cart_items_by_ref_id(cart_ref_id, user_id)
        # delivery fee
        delivery_fee = 2000 if cart_items else 0
        cart_ref_id = cart_items[0]["cart_ref_id"] if cart_items else None

        total_price = sum(item["amount"] for item in cart_items) + delivery_fee

        res_data = data_cache(
            f"products:finalized_carts:{cart_ref_id}:{user_id}",
            {
                "cart_items": cart_items,
                "total_price": total_price,
                "delivery_fee": delivery_fee,
                "cart_ref_id": cart_ref_id,
                "user_email": current_user.email,
            },
            60,
        )

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Cart finalized successfully",
            **res_data,
        )
    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# payment verify
@products.post("/verify_payment")
@jwt_required()
def verify_payment():
    try:
        from src.worker.tasks.bg_tasks import verify_paystack_transaction

        data = request.get_json()
        reference = data.get("reference")
        cart_ref_id = data.get("cart_ref_id")
        address = data.get("address")
        address_id = data.get("address_id")
        user_id = current_user.id
        if not reference:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Reference is required",
            )
        if not cart_ref_id:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Cart reference ID is required",
            )
        if not address and not address_id:
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Address is required",
            )
        if address_id:
            address = get_address(address_id)
            if not address:
                return return_response(
                    http_status_codes.HTTP_400_BAD_REQUEST,
                    status=StatusMessage.FAILED,
                    message="Invalid address ID",
                )
            address_id = address.id
        else:
            address = add_order_address(user_id, address)
            address_id = address.id
        if not get_cart_items_by_ref_id(cart_ref_id, user_id):
            return return_response(
                http_status_codes.HTTP_400_BAD_REQUEST,
                status=StatusMessage.FAILED,
                message="Invalid cart reference ID",
            )

        order = create_order(user_id, address_id)

        order_id = order.id

        verify_paystack_transaction.delay(user_id, reference, cart_ref_id, order_id)

        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Payment verification started successfully",
        )
    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# get ordrer addresses
@products.get("/order_address")
@jwt_required()
def order_address():
    try:
        order_address = get_order_address(current_user.id)
        res_data = data_cache(
            f"products:order_address:{current_user.id}",
            [address.to_dict() for address in order_address],
            60,
        )
        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Order address retrieved successfully",
            order_address=res_data,
        )
    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )


# get orders
@products.get("/orders")
@jwt_required()
def orders():
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 10))

        # get orders by created_at desc
        orders = Order.query.filter_by(user_id=current_user.id).order_by(
            Order.created_at.desc()
        ).paginate(
            page=page, per_page=per_page, error_out=False
        )

        order_list = [
            {
                "id": order.id,
                "order_number": order.order_number,
                "address": order.order_address.address,
                "created_at": format_datetime(order.created_at),
                "product_purchased": [
                    product_purchased.to_dict()
                    for product_purchased in order.product_purchased
                ],
                "total_amount": sum(
                    product_purchased.amount
                    for product_purchased in order.product_purchased
                ),
            }
            for order in orders.items
        ]

        order_returned_dict = {
            "orders": order_list,
            "total_items": orders.total,
            "total_pages": orders.pages,
            "page": orders.page,
            "per_page": orders.per_page,
        }

        res_data = data_cache(
            f"products:orders:{current_user.id}",
            order_returned_dict,
            60,
        )
        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Orders retrieved successfully",
            **res_data,
        )
    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )
