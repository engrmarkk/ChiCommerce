from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from sqlalchemy import MetaData
from flask_migrate import Migrate
from flask_cors import CORS
from flask_mail import Mail

# from flask_socketio import SocketIO

naming_convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


mail = Mail()
db = SQLAlchemy(metadata=MetaData(naming_convention=naming_convention))
jwt = JWTManager()
migrate = Migrate()
# socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")
cors = CORS()
