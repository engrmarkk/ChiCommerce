import os
import base64
import requests
from src.constants.env_constant import (
    MONNIFY_API_KEY,
    MONNIFY_CONTRACT_CODE,
    MONNIFY_SECRET_KEY,
)
from src.logger import logger
from src.connections.redis_connection import redis_conn


class MonnifyBase:
    def __init__(self):
        try:
            self.api_key = MONNIFY_API_KEY
            self.url = "https://sandbox.monnify.com/api"
            self.secret_key = MONNIFY_SECRET_KEY
            self.contract_code = MONNIFY_CONTRACT_CODE
            self.token = self.get_access_token()
            self.headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            }
        except Exception as e:
            logger.exception(e)

    def get_access_token(self):
        try:
            access_token = redis_conn.get("monnify_access_token")
            if access_token:
                logger.info("Access token found in redis")
                return access_token
            # use basic auth for both api key and secret key
            auth_bytes = base64.b64encode(
                f"{self.api_key}:{self.secret_key}".encode("utf-8")
            ).decode("utf-8")
            login_headers = {
                "Authorization": f"Basic {auth_bytes}",
                "Content-Type": "application/json",
            }
            response = requests.post(f"{self.url}/v1/auth/login", headers=login_headers)
            if response.status_code == 200:
                data = response.json()
                access_token = data.get("responseBody").get("accessToken")
                # save to redis
                redis_conn.set("monnify_access_token", access_token, expire=3600)
                logger.info("Access token saved in redis")
                return access_token
            else:
                return None
        except Exception as e:
            logger.exception(e)
            return None
