from . import webhooks_blp
from src.logger import logger
from src.utils.util import return_response, compute_transaction_hash
from src.constants import http_status_codes
from src.constants.status_message import StatusMessage
from src.constants.env_constant import EXCEPTION_MESSAGE
from flask import request

MONNIFY_PREFIX = "monnify"


@webhooks_blp.post(f"/{MONNIFY_PREFIX}/payment_successful")
def monnify_webhooks():
    try:
        raw_payload = request.get_data()
        signature = request.headers.get("monnify-signature")
        computed = compute_transaction_hash(raw_payload)
        logger.info(f"computed: {computed}")
        logger.info(f"signature: {signature}")
        if signature != computed:
            logger.info("Invalid signature")
            return return_response(
                http_status_codes.HTTP_403_FORBIDDEN,
                status=StatusMessage.FAILED,
                message="Invalid signature",
            )
        logger.info("Valid signature")
        return return_response(
            http_status_codes.HTTP_200_OK,
            status=StatusMessage.SUCCESS,
            message="Monnify webhooks retrieved successfully",
        )
    except Exception as e:
        logger.exception(e)
        return return_response(
            http_status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            status=StatusMessage.FAILED,
            message=EXCEPTION_MESSAGE,
        )
