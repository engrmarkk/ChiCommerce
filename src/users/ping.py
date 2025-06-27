from flask import Blueprint
from src.utils.util import return_response
from src.constants import http_status_codes
from src.constants.status_message import StatusMessage

ping_blp = Blueprint("ping_blp", __name__)

# Test
@ping_blp.get("/ping")
def ping():
    return return_response(
        http_status_codes.HTTP_200_OK,
        status=StatusMessage.SUCCESS,
        message="Ping successful",
    )
