from src.integrations.monnify.base import MonnifyBase
from src.logger import logger
import requests


class MonnifyServices(MonnifyBase):
    def get_transaction(self, transaction_ref):
        try:
            logger.info(f"transaction_ref: {transaction_ref}")
            response = requests.get(
                f"{self.url}/v2/transactions/{transaction_ref}", headers=self.headers
            )
            data = response.json()
            status_code = response.status_code
            logger.info(f"data@get_transaction: {data}")
            return data, status_code
        except Exception as e:
            logger.exception(e)
            return {}, 500
