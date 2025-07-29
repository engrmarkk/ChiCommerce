from celery import Celery, shared_task
from src import create_app
from src.constants.env_constant import REDIS_URL
from dotenv import load_dotenv
from src.logger import logger
import src.worker.schedule as celeryConfig

load_dotenv()


app = create_app()


def make_celery(app=app):
    """
    As described in the doc
    """
    celery = Celery(
        app.import_name,
        backend=f"{REDIS_URL}?ssl_cert_reqs=CERT_NONE",
        broker=f"{REDIS_URL}?ssl_cert_reqs=CERT_NONE",
    )
    celery.conf.update(app.config)
    celery.config_from_object(celeryConfig)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery


celery = make_celery()


@shared_task
def add_numbers(x, y):
    logger.info("Adding")
    return x + y
