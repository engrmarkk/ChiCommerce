# from extensions import db
from enum import Enum
from passlib.hash import pbkdf2_sha256 as hasher
from sqlalchemy.ext.hybrid import hybrid_property
import re
import datetime
from flask_sqlalchemy import SQLAlchemy
import random
import string
from sqlalchemy import ForeignKey, Index
from sqlalchemy.sql import exists
from sqlalchemy.orm import relationship
from flask_login import UserMixin
from src.utils.util import format_datetime
import uuid

from datetime import datetime, timedelta, date

db = SQLAlchemy()


def random_id():
    return str(uuid.uuid4().hex)


class TransactionType(Enum):
    deposit = "deposit"
    withdrawal = "withdrawal"
    payment = "payment"
    refund = "refund"


class TransactionStatus(Enum):
    success = "success"
    failed = "failed"


# User Model
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(50), primary_key=True, default=random_id)
    username = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.Text, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    reset_otp = db.Column(db.String(10), nullable=True)
    otp_expiration = db.Column(db.DateTime, nullable=True)
    verification_token = db.Column(db.String(255), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "is_admin": self.is_admin,
            "is_active": self.is_active,
            "created_at": format_datetime(self.created_at),
            "email_verified": self.email_verified,
            "email": self.email,
        }


# Category Model
class Category(db.Model):
    __tablename__ = "category"
    id = db.Column(db.String(50), primary_key=True, default=random_id)
    name = db.Column(db.String(50), nullable=False)
    image = db.Column(db.String(500), nullable=False)

    products = db.relationship("Products", backref="category")

    def to_dict(self):
        return {"id": self.id, "name": self.name, "image": self.image}


# Products Model
class Products(db.Model):
    __tablename__ = "products"
    id = db.Column(db.String(50), primary_key=True, default=random_id)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    color = db.Column(db.String(50), nullable=False)
    model = db.Column(db.String(50), nullable=False)
    out_of_stock = db.Column(db.Boolean, default=False)
    category_id = db.Column(db.String(50), db.ForeignKey("category.id"), nullable=False)
    image = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    specification = db.relationship(
        "Specification", backref="products", cascade="all, delete-orphan"
    )
    product_images = db.relationship(
        "ProductImages", backref="products", cascade="all, delete-orphan"
    )

    favorites = db.relationship(
        "Favorite", backref="products", cascade="all, delete-orphan"
    )
    purchased = db.relationship(
        "ProductPurchased", backref="products", cascade="all, delete-orphan"
    )

    @classmethod
    def is_favorited_by(cls, product_id, user_id):
        return db.session.query(
            exists()
            .where(
                Favorite.product_id == product_id,
            )
            .where(Favorite.user_id == user_id)
        ).scalar()

    def to_dict(self, user_id=None, all_products=False):
        returned_dict = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "price": self.price,
            "model": self.model,
            "color": self.color,
            "out_of_stock": self.out_of_stock,
            "category_id": self.category_id,
            "category_name": self.category.name,
            "image": self.image,
            "created_at": format_datetime(self.created_at),
        }
        if user_id is not None:
            returned_dict["favorited"] = Products.is_favorited_by(self.id, user_id)
        else:
            returned_dict["favorited"] = False
        if all_products:
            returned_dict["specifications"] = [
                spec.to_dict() for spec in self.specification
            ]
            returned_dict["product_images"] = [
                image.to_dict() for image in self.product_images
            ]
        return returned_dict


# product images
class ProductImages(db.Model):
    __tablename__ = "product_images"
    id = db.Column(db.String(50), primary_key=True, default=random_id)
    image = db.Column(db.Text, nullable=False)
    product_id = db.Column(db.String(50), db.ForeignKey("products.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self):
        return {"id": self.id, "image": self.image}


class Specification(db.Model):
    __tablename__ = "specification"
    id = db.Column(db.String(50), primary_key=True, default=random_id)
    name = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)
    product_id = db.Column(db.String(50), db.ForeignKey("products.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self):
        return {"id": self.id, "name": self.name, "description": self.description}


class Cart(db.Model):
    __tablename__ = "cart"
    id = db.Column(db.String(50), primary_key=True, default=random_id)
    user_id = db.Column(db.String(50), db.ForeignKey("users.id"), nullable=False)
    product_id = db.Column(db.String(50), db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    cart_ref_id = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

    product = db.relationship("Products", backref="cart")

    def to_dict(self):
        return {
            "id": self.id,
            # "user_id": self.user_id,
            "product_id": self.product_id,
            "product_name": self.product.name,
            "quantity": self.quantity,
            "amount": round(self.quantity * self.product.price, 2),
            "cart_ref_id": self.cart_ref_id,
            "product_image": self.product.image,
            "product_price": self.product.price,
        }


# favorite
class Favorite(db.Model):
    __tablename__ = "favorite"
    id = db.Column(db.String(50), primary_key=True, default=random_id)
    user_id = db.Column(db.String(50), db.ForeignKey("users.id"), nullable=False)
    product_id = db.Column(db.String(50), db.ForeignKey("products.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    # create index
    __table_args__ = (
        Index(
            "user_product_index",
            "user_id",
            "product_id",
            unique=True,
        ),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "product": self.products.to_dict(),
        }


# product purchased
class ProductPurchased(db.Model):
    __tablename__ = "product_purchased"
    id = db.Column(db.String(50), primary_key=True, default=random_id)
    user_id = db.Column(db.String(50), db.ForeignKey("users.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    product_id = db.Column(db.String(50), db.ForeignKey("products.id"), nullable=False)
    order_id = db.Column(db.String(50), db.ForeignKey("order.id"), nullable=False)
    transaction_id = db.Column(
        db.String(50), db.ForeignKey("transaction.id"), nullable=False
    )
    quantity = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "product_id": self.product_id,
            "amount": self.amount,
            "quantity": self.quantity,
            "product_name": self.products.name,
            "created_at": format_datetime(self.created_at),
        }

    def __repr__(self):
        return f"<ProductPurchased {self.id} - {self.products.name}>"


# Order
class Order(db.Model):
    __tablename__ = "order"
    id = db.Column(db.String(50), primary_key=True, default=random_id)
    order_number = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.String(50), db.ForeignKey("users.id"), nullable=False)
    address_id = db.Column(
        db.String(50), db.ForeignKey("order_address.id"), nullable=False
    )
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    # product purchased relationship
    product_purchased = db.relationship(
        "ProductPurchased", backref="order", lazy="joined"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "created_at": format_datetime(self.created_at),
        }


class OrderAddress(db.Model):
    __tablename__ = "order_address"
    id = db.Column(db.String(50), primary_key=True, default=random_id)
    user_id = db.Column(db.String(50), db.ForeignKey("users.id"), nullable=False)
    address = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    # order relationship
    orders = db.relationship("Order", backref="order_address", lazy="joined")

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "address": self.address,
            "created_at": format_datetime(self.created_at),
        }


class Transaction(db.Model):
    id = db.Column(db.String(50), primary_key=True, default=random_id)
    user_id = db.Column(db.String(50), db.ForeignKey("users.id"), nullable=False)
    amount = db.Column(db.Float, default=0.0)
    channel = db.Column(db.String(50))
    transaction_id = db.Column(db.String(50))
    transaction_type = db.Column(
        db.Enum(TransactionType), default=TransactionType.payment
    )
    transaction_status = db.Column(
        db.Enum(TransactionStatus), default=TransactionStatus.success
    )
    authorization_dict = db.Column(db.JSON)
    ip_address = db.Column(db.String(50))
    reference_number = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

    product_purchased = db.relationship(
        "ProductPurchased",
        backref="transaction",
    )

    __table_args__ = (
        Index("ix_transaction_created_at", "created_at"),
        Index("ix_transaction_user_id", "user_id"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M"),
            "amount": self.amount,
            "channel": self.channel,
            "transaction_type": self.transaction_type.value,
            "transaction_status": self.transaction_status.value,
            "reference_number": self.reference_number,
        }
