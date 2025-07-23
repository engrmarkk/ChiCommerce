from src.worker.config import celery, shared_task
from src.logger import logger


@shared_task
def test_job():
    logger.info("Test Job")
    return True
