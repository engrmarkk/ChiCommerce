from src.model.database import (
    db,
    Specification,
    Products,
    ProductImages,
    Cart,
    Transaction,
    ProductPurchased,
    OrderAddress,
    Order,
)
import uuid
from src.logger import logger
import string
import random


# generate cart_ref_id
def generate_cart_ref_id():
    return str(uuid.uuid4().hex)


# formulate order_number
def generate_order_number():
    return "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(10)
    )


def update_product_specifications(product_id, specifications):
    product = Products.query.get(product_id)
    if not product:
        return None
    for specification in specifications:
        if specification["id"]:
            specs_obj = Specification.query.filter(
                Specification.id == specification["id"]
            ).first()
            if specs_obj:
                specs_obj.name = specification["name"] or specs_obj.name
                specs_obj.description = (
                    specification["description"] or specs_obj.description
                )
                db.session.commit()
        else:
            if Specification.query.filter(
                Specification.name == specification["name"],
                Specification.product_id == product_id,
            ).first():
                continue
            specs_obj = Specification(
                name=specification["name"], description=specification["description"]
            )
            db.session.add(specs_obj)
    db.session.commit()
    return product


def update_product_images(product_id, images):
    product = Products.query.get(product_id)
    if not product:
        return None
    for image in images:
        if isinstance(image, dict):
            if image["id"]:
                image_obj = ProductImages.query.filter(
                    ProductImages.id == image["id"]
                ).first()
                if image_obj:
                    image_obj.image = image["image"] or image_obj.image
                    db.session.commit()
        elif isinstance(image, str):
            image_obj = ProductImages(image=image, product_id=product_id)
            db.session.add(image_obj)
    db.session.commit()
    return product


# add to cart
def add_to_cart(user_id, product_id, quantity, cart_ref_id):
    try:
        cart_item = Cart(
            user_id=user_id,
            product_id=product_id,
            quantity=quantity,
            cart_ref_id=cart_ref_id,
        )
        db.session.add(cart_item)
        db.session.commit()
        return cart_item
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error adding to cart: {e}")
        return None


# get cart items by ref_id
def get_cart_items_by_ref_id(cart_ref_id, user_id):
    try:
        cart_items = Cart.query.filter_by(
            cart_ref_id=cart_ref_id, user_id=user_id
        ).all()
        return [item.to_dict() for item in cart_items]
    except Exception as e:
        logger.exception(f"Error retrieving cart items: {e}")
        return []


def get_cart_items_by_ref_id_instance(cart_ref_id, user_id):
    try:
        cart_items = Cart.query.filter_by(
            cart_ref_id=cart_ref_id, user_id=user_id
        ).all()
        return cart_items
    except Exception as e:
        logger.exception(f"Error retrieving cart items: {e}")
        return []


def finalize_cart_item(products, user_id):
    try:
        cart_ref_id = generate_cart_ref_id()
        for product in products:
            # if product_id and quantity, add to cart directly
            if product.get("product_id") and product.get("quantity"):
                cart_item = add_to_cart(
                    user_id=user_id,
                    product_id=product["product_id"],
                    quantity=product["quantity"],
                    cart_ref_id=cart_ref_id,
                )
        return get_cart_items_by_ref_id(cart_ref_id, user_id)
    except Exception as e:
        logger.exception(f"Error finalizing cart item: {e}")
        return None


def clear_cart(user_id, cart_ref_id):
    try:
        cart_items = get_cart_items_by_ref_id_instance(cart_ref_id, user_id)
        for item in cart_items:
            db.session.delete(item)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error clearing cart: {e}")
        return None


def process_cart_payment(user_id, data, cart_ref_id, order_id):
    carts_items = get_cart_items_by_ref_id(cart_ref_id, user_id)
    trans = save_transaction(data, user_id)
    for cart in carts_items:
        save_product_purchased(
            cart.get("product_id"),
            user_id,
            cart.get("quantity") * cart.get("product_price"),
            trans.id,
            cart.get("quantity"),
            order_id,
        )
        # reduce_land_plot(cart.property_id, cart.count)
    return


def save_transaction(data, user_id):
    new_trans = Transaction(
        amount=float(data.get("amount")) / 100,
        user_id=user_id,
        channel=data.get("channel"),
        transaction_id=data.get("id"),
        authorization_dict=data.get("authorization", {}),
        ip_address=data.get("ip_address"),
        reference_number=data.get("reference"),
    )
    db.session.add(new_trans)
    db.session.commit()
    return new_trans


def save_product_purchased(
    product_id, user_id, amount, transaction_id, quantity, order_id
):
    new_purchase = ProductPurchased(
        product_id=product_id,
        user_id=user_id,
        amount=amount,
        transaction_id=transaction_id,
        quantity=quantity,
        order_id=order_id,
    )
    db.session.add(new_purchase)
    db.session.commit()
    return new_purchase


# get order address order desc by created_at
def get_order_address(user_id):
    return (
        OrderAddress.query.filter_by(user_id=user_id)
        .order_by(OrderAddress.created_at.desc())
        .all()
    )


# add order address
def add_order_address(user_id, address):
    try:
        ex_address = OrderAddress.query.filter_by(
            user_id=user_id, address=address
        ).first()
        if ex_address:
            return ex_address
        order_address = OrderAddress(user_id=user_id, address=address)
        db.session.add(order_address)
        db.session.commit()
        return order_address
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error adding order address: {e}")
        return None


def create_order(user_id, address_id):
    try:
        order_number = generate_order_number()
        order = Order(user_id=user_id, order_number=order_number, address_id=address_id)
        db.session.add(order)
        db.session.commit()
        return order
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error creating order: {e}")
        return None


# return address using address id
def get_address(address_id):
    return OrderAddress.query.filter_by(id=address_id).first()


# get all orders with order by created_at desc and filter with query (urder number)
def get_all_orders(query, page, per_page):
    orders_query = Order.query.filter(
        Order.order_number.ilike(f"%{query}%") if query else True
    ).paginate(page=page, per_page=per_page, error_out=False)

    resp = {
        "orders": [order.admin_to_dict() for order in orders_query.items],
        "total_pages": orders_query.pages,
        "total_items": orders_query.total,
        "page": orders_query.page,
        "per_page": orders_query.per_page,
        "has_next": orders_query.has_next,
        "has_prev": orders_query.has_prev,
    }
    return resp
