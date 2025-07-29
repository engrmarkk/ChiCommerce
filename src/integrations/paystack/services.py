from .base import PaystackBase
import requests
from src.logger import logger


class PaystackEndpoints(PaystackBase):
    def verify_transaction(self, reference):
        """
        Verifies a Paystack transaction by reference.
        Returns (response_json, status_code)
        """
        try:
            url = f"{self.url}/transaction/verify/{reference}"
            logger.info(f"url: {url}")
            response = requests.get(url, headers=self.header)
            logger.info(f"g=header: {self.header}")
            response.raise_for_status()
            logger.info(f"response: {response.json()}")
            return response.json(), response.status_code
        except requests.exceptions.HTTPError as http_err:
            logger.info(f"HTTP error occurred: {http_err}")
            return {}, 500
        except requests.exceptions.RequestException as req_err:
            logger.info(f"Request exception occurred: {req_err}")
            return {}, 500
        except Exception as e:
            logger.info(f"An error occurred: {e}")
            return {}, 500
