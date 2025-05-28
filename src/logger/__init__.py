import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    # filename='/app/logs/app.log',
    # filename="app.log",
    # filemode="a",
    datefmt="%d-%b-%Y %H:%M:%S",
)

logger = logging.getLogger(__name__)
