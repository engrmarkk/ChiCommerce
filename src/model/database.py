# from extensions import db
from enum import Enum
from passlib.hash import pbkdf2_sha256 as hasher
from sqlalchemy import Enum as SQLAlchemyEnum
from sqlalchemy.ext.hybrid import hybrid_property
import re
import datetime
from flask_sqlalchemy import SQLAlchemy
import random
import string
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin

from datetime import datetime, timedelta, date

db = SQLAlchemy()


def random_id():
    return "".join(random.choice(string.ascii_letters) for _ in range(10))






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
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
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
            "created_at": self.created_at.isoformat(),
            "email_verified": self.email_verified,
            "email": self.email
        }

# Category Model
class Category(db.Model):
    __tablename__ = "category"
    id = db.Column(db.String(50), primary_key=True, default=random_id)
    name = db.Column(db.String(50), nullable=False)
    image = db.Column(db.String(500), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "image": self.image
        }

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
    category_id = db.Column(db.String(50), db.ForeignKey('category.id'), nullable=False)
    image = db.Column(db.String(500), nullable=False)
    specification_1 = db.Column(db.String(100), nullable=True)
    specification_2 = db.Column(db.String(100), nullable=True)
    specification_3 = db.Column(db.String(100), nullable=True)
    specification_4 = db.Column(db.String(100), nullable=True)
    specification_5 = db.Column(db.String(100), nullable=True)
    specification_6 = db.Column(db.String(100), nullable=True)
    specification_7 = db.Column(db.String(100), nullable=True)
    specification_8 = db.Column(db.String(100), nullable=True)
    specification_9 = db.Column(db.String(100), nullable=True)
    specification_10 = db.Column(db.String(100), nullable=True)
    specification_11 = db.Column(db.String(100), nullable=True)
    specification_12 = db.Column(db.String(100), nullable=True)
    specification_13 = db.Column(db.String(100), nullable=True)
    specification_14 = db.Column(db.String(100), nullable=True)
    specification_15 = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    category = db.relationship('Category', backref='products')

    def to_dict(self):
        return {
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
            "specification_1": self.specification_1,
            "specification_2": self.specification_2,
            "specification_3": self.specification_3,
            "specification_4": self.specification_4,
            "specification_5": self.specification_5,
            "specification_6": self.specification_6,
            "specification_7": self.specification_7,
            "specification_8": self.specification_8,
            "specification_9": self.specification_9,
            "specification_10": self.specification_10,
            "specification_11": self.specification_11,
            "specification_12": self.specification_12,
            "specification_13": self.specification_13,
            "specification_14": self.specification_14,
            "specification_15": self.specification_15,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }



