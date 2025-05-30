from flask import jsonify, request
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    verify_jwt_in_request,
    get_jwt,
)
from functools import wraps
from http import HTTPStatus


def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            try:
                print("Authorization Header:", request.headers.get("Authorization"))

                verify_jwt_in_request()
                jwt_data = get_jwt()
                user_id = get_jwt_identity()

                if not jwt_data.get("is_admin", False):
                    return (
                        jsonify({"message": "Admin access required"}),
                        HTTPStatus.FORBIDDEN,
                    )

                user = User.query.get(user_id)
                if not user:
                    return jsonify({"message": "User not found"}), HTTPStatus.NOT_FOUND

                if not hasattr(user, "is_admin") or not user.is_admin:
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

        return decorator

    return wrapper
