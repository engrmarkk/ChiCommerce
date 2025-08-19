import os
from src.constants.env_constant import MONNIFY_API_KEY, MONNIFY_CONTRACT_CODE


class MonnifyBase:
    def __init__(self):
        try:
            self.api_key = MONNIFY_API_KEY
            self.url = "https://sandbox.monnify.com"
            self.contract_code = MONNIFY_CONTRACT_CODE
        except Exception as e:
            print(e, "error from monnify base")
