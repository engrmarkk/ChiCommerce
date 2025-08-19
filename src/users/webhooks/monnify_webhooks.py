from . import webhooks_blp
from src.logger import logger
from src.utils.util import return_response
from src.constants import http_status_codes
from src.constants.status_message import StatusMessage
from src.constants.env_constant import EXCEPTION_MESSAGE

MONNIFY_PREFIX = "monnify"

@webhooks_blp.get(f"/{MONNIFY_PREFIX}/payment_successful")
def monnify_webhooks():
    try:
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
