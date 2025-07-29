from src.model.database import (
    db,
    Specification,
    Products,
    ProductImages,
    Cart,
    Transaction,
    ProductPurchased,
)
import uuid
from src.logger import logger


# generate cart_ref_id
def generate_cart_ref_id():
    return str(uuid.uuid4().hex)


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
        cart_items = get_cart_items_by_ref_id(cart_ref_id, user_id)
        for item in cart_items:
            db.session.delete(item)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error clearing cart: {e}")
        return None


def process_cart_payment(user_id, data, cart_ref_id):
    carts_items = get_cart_items_by_ref_id(cart_ref_id, user_id)
    trans = save_transaction(data, user_id)
    for cart in carts_items:
        save_product_purchased(
            cart.product_id,
            user_id,
            cart.quantity * cart.product.price,
            trans.id,
            cart.quantity,
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


def save_product_purchased(product_id, user_id, amount, transaction_id, quantity):
    new_purchase = ProductPurchased(
        product_id=product_id,
        user_id=user_id,
        amount=amount,
        transaction_id=transaction_id,
        quantity=quantity,
    )
    db.session.add(new_purchase)
    db.session.commit()
    return new_purchase
