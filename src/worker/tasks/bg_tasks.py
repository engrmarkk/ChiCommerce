from celery import shared_task
from datetime import datetime
from src.model.database import db, Cart
from src.func import get_cart_items_by_ref_id, clear_cart, process_cart_payment
from src.logger import logger
from src.integrations.paystack.services import PaystackEndpoints

pay_stack = PaystackEndpoints()


@shared_task
def verify_paystack_transaction(user_id, ref, cart_ref_id):
    try:
        res = pay_stack.verify_transaction(ref)
        if res[1] == 200:
            process_cart_payment(user_id, res[0].get("data"))
            # user_carts = get_cart_items_by_ref_id(cart_ref_id, user_id)
            clear_cart(user_id, cart_ref_id)
            return True
        return False
    except Exception as e:
        logger.error(f"Error verifying transaction: {e}")
        logger.exception(e)
        return False
