from celery import Celery, shared_task
from src import create_app
from src.constants.env_constant import REDIS_URL
from dotenv import load_dotenv
from src.logger import logger
import src.worker.schedule as celeryConfig

load_dotenv()


app = create_app()


def make_celery(app=app):
    celery = Celery(
        app.import_name,
        backend=f"{REDIS_URL}?ssl_cert_reqs=CERT_REQUIRED",
        broker=f"{REDIS_URL}?ssl_cert_reqs=CERT_REQUIRED",
    )
    celery.conf.update(app.config)
    celery.config_from_object(celeryConfig)

    # Add explicit connection pool settings
    celery.conf.broker_pool_limit = 10  # Don't use None — that causes unbounded pools
    celery.conf.redis_socket_keepalive = True
    celery.conf.redis_socket_timeout = 30
    celery.conf.redis_retry_on_timeout = True

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
