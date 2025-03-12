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

from datetime import datetime, timedelta, date

db = SQLAlchemy()


def random_id():
    return "".join(random.choice(string.ascii_letters) for _ in range(10))


class User(db.Model):
    __tablename__ = "users"


    id = db.Column(db.String(50), primary_key=True, default=random_id)
    username = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.Text, nullable=False)
    # profile_pic = db.Column(db.Text, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    reset_otp = db.Column(db.String(10), nullable=True)
    otp_expiration = db.Column(db.DateTime, nullable=True)
    verification_token = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    
    
    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "password": self.password,
            # "profile_pic": self.profile_pic,
            "is_admin": self.is_admin,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "email_verified": self.email_verified,
            "email": self.email
        }