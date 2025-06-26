import base64
import datetime
import hashlib
import hmac
import re
import time
from flask import jsonify
from flask_jwt_extended import create_access_token
from io import BytesIO
from passlib.hash import pbkdf2_sha256 as sha256

from src.constants.env_constant import ACCESS_TOKEN_EXPIRES
from src.logger import logger


def return_response(status_code, status=None, message=None, **data):
    res_data = {
        "status": status,
        "message": message,
    }
    res_data.update(data)

    return jsonify(res_data), status_code


def convert_binary(base64_file):
    try:
        logger.info("got here")
        binary_data = base64.b64decode(base64_file)
        # Convert binary data to a file-like object
        file_like = BytesIO(binary_data)
        logger.info(file_like)
        return file_like
    except Exception as e:
        logger.exception(e)
        return None


def generate_signature(params_to_sign, api_secret):
    try:
        params_to_sign["timestamp"] = int(time.time())
        sorted_params = "&".join(
            [f"{k}={params_to_sign[k]}" for k in sorted(params_to_sign)]
        )
        to_sign = f"{sorted_params}{api_secret}"
        signature = hmac.new(
            api_secret.encode("utf-8"), to_sign.encode("utf-8"), hashlib.sha1
        ).hexdigest()
        return signature
    except Exception as e:
        logger.exception(e)
        return None


def format_datetime(datetime_obj, format="%Y-%m-%d %H:%M:%S"):
    return datetime_obj.strftime(format) if datetime_obj else None
