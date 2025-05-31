from flask import render_template
from flask_mail import Message

from src.constants.env_constant import SENDER_EMAIL, SENDER_NAME
from src.extentions.extensions import mail
from src.logger import logger


def send_mail(data):
    try:
        msg = Message(
            subject=data["subject"],  # Dynamic subject passed to the function
            sender=f"{SENDER_NAME} <{SENDER_EMAIL}>",
            recipients=[data["email"]],
        )
        msg.html = render_template(data["template"], **data)
        mail.send(msg)
        return True
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        return False
