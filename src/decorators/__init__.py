from flask import jsonify, request
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    verify_jwt_in_request,
    get_jwt,
    current_user,
)
from functools import wraps
from http import HTTPStatus


def admin_required():
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            try:
                if not current_user.is_admin:
                    return (
                        jsonify({"message": "Admin privileges required"}),
                        HTTPStatus.FORBIDDEN,
                    )
                return fn(*args, **kwargs)
            except Exception as e:
                return (
                    jsonify({"message": "Authentication failed", "error": str(e)}),
                    HTTPStatus.UNAUTHORIZED,
                )

        return wrapped

    return decorator


def admin_not_required():
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            try:
                if current_user.is_admin:
                    return (
                        jsonify({"message": "Admin privileges revoked"}),
                        HTTPStatus.FORBIDDEN,
                    )
                return fn(*args, **kwargs)
            except Exception as e:
                return (
                    jsonify({"message": "Authentication failed", "error": str(e)}),
                    HTTPStatus.UNAUTHORIZED,
                )

        return wrapped

    return decorator