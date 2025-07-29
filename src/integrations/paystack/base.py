import os
from dotenv import load_dotenv
from src.constants.env_constant import PAYSTACK_SECRET


load_dotenv()


class PaystackBase:
    def __init__(self):
        try:
            self.url = "https://api.paystack.co"
            self.secret = PAYSTACK_SECRET
            self.header = {"Authorization": f"Bearer {self.secret}"}
            self.country = "nigeria"
        except Exception as e:
            print(e, "error from paystack base")
