from . import color, config
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

engine = create_engine(
    f"postgresql://{config['POSTGRES_USER']}:{config['POSTGRES_PASSWORD']}@{config['POSTGRES_HOST']}:{config['POSTGRES_PORT']}/{config['POSTGRES_DB']}"
)

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
