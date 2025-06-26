import cloudinary.api
import cloudinary.uploader
import os
import time
from dotenv import load_dotenv
from flask import Blueprint, request

import src.cloudinary_config as cloudinary_config
from src.constants.http_status_codes import *
from src.utils.util import convert_binary, generate_signature, return_response
from src.logger import logger

cloudnary = Blueprint("cloudnary", __name__)


load_dotenv()


@cloudnary.route(f"/manage-image", methods=["POST"])
def manage_file():
    try:
        data = request.get_json()
        image = data.get("image", None)
        public_id = data.get("public_id", None)
        action = data.get("action", None)
        folder = data.get("folder", None)

        logger.info(data)

        cloud_name = (os.environ.get("CLOUD_NAME"),)
        api_key = (os.environ.get("API_KEY"),)
        api_secret = (os.environ.get("API_SECRET"),)

        cloud_name = str(cloud_name[0]) if isinstance(cloud_name, tuple) else cloud_name
        api_key = str(api_key[0]) if isinstance(api_key, tuple) else api_key
        api_secret = str(api_secret[0]) if isinstance(api_secret, tuple) else api_secret

        logger.info(cloud_name)
        logger.info(api_key)
        logger.info(api_secret)

        if not action:
            return return_response(
                HTTP_400_BAD_REQUEST,
                message="Action is required",
            )

        if action == "upload" and not image:
            return return_response(
                HTTP_400_BAD_REQUEST,
                message="File is required",
            )

        if not public_id:
            return return_response(
                HTTP_400_BAD_REQUEST,
                message="Public ID is required",
            )

        file = convert_binary(image) if action == "upload" else None

        logger.info(file)

        params_to_sign = {
            "public_id": public_id,
            "timestamp": int(time.time()),
        }
        signature = generate_signature(params_to_sign, api_secret)

        params_to_sign["signature"] = signature

        logger.info(signature)
        logger.info(params_to_sign)

        params_to_sign["folder"] = folder if folder else None

        if action == "upload":
            logger.info(action)
            result = cloudinary.uploader.upload(file, **params_to_sign)
            logger.info(result)
            img_url = result["secure_url"]

            return return_response(
                HTTP_200_OK,
                message="File uploaded successfully",
                data={
                    "img_url": img_url,
                    "public_id": public_id,
                    "signature": signature,
                },
            )
        elif action == "destroy":
            params_to_sign["public_id"] = (
                f"{folder}/{public_id}" if folder else public_id
            )
            result = cloudinary.uploader.destroy(**params_to_sign)
            logger.info(params_to_sign)
            logger.info(result)

            return (
                return_response(
                    HTTP_200_OK,
                    message="Image deleted successfully",
                )
                if result["result"] == "ok"
                else return_response(
                    HTTP_400_BAD_REQUEST,
                    message="Image not found",
                )
            )
        else:
            return return_response(
                HTTP_400_BAD_REQUEST,
                message="Invalid action",
            )

    except KeyError as e:
        logger.exception(e)
        return return_response(
            HTTP_400_BAD_REQUEST,
            message="All fields are required",
        )
    except Exception as e:
        logger.exception(e)
        return return_response(
            HTTP_500_INTERNAL_SERVER_ERROR,
            message="Network error",
        )
