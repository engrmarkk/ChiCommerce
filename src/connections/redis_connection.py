import redis

from src.constants.env_constant import REDIS_URL, REDIS_EXPIRE_TIME
from src.logger import logger


class RedisConnection:
    def __init__(self, url=REDIS_URL):
        try:
            self.connection = redis.Redis.from_url(url, decode_responses=True)
        except Exception as e:
            logger.exception(e)

    def get_connection(self):
        return self.connection

    def close_connection(self):
        self.connection.close()

    def set(self, key, value, expire=REDIS_EXPIRE_TIME):
        return self.connection.set(key, value, ex=expire)

    def get(self, key):
        return self.connection.get(key)

    def delete(self, key):
        return self.connection.delete(key)

    def pipeline(self):
        return self.connection.pipeline()


redis_conn = RedisConnection()
