from . import color, config
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

if config["ENV"] == "DEV":
    SQLALCHEMY_DATABASE_URL = "sqlite:///./db.sqlite"
elif config["ENV"] == "PROD":
    SQLALCHEMY_DATABASE_URL = f"postgresql://{config['POSTGRES_USER']}:{config['POSTGRES_PASSWORD']}@postgres/{config['POSTGRES_DB']}"
else:
    raise Exception("Invalid environment!")

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)

Base = declarative_base()


class SessionManager:
    def __enter__(self):
        self.db = SessionLocal()
        return self.db

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            print(
                f"{color.RED} We somehow failed in a DB operation. Auto-rollbacking...{color.ENDCOLOR}"
            )
            self.db.rollback()
        self.db.close()
        return False


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
