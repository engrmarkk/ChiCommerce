from flask import Blueprint

webhooks_blp = Blueprint("webhooks_blp", __name__)

from .monnify_webhooks import *
