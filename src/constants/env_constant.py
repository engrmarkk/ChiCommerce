from dotenv import load_dotenv

load_dotenv()

FRONTEND_VERIFICATION_URL = os.getenv("FRONTEND_VERIFICATION_URL")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_NAME = os.getenv("SENDER_NAME")
FRONTEND_LOGIN_URL = os.getenv("FRONTEND_LOGIN_URL")
