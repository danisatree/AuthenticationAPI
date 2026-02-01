from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncAttrs, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import load_config

config = load_config()

if config.db.type == "postgresql":
    DATABASE_URL = config.db.postgresql_url
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL must be set when using PostgreSQL")
else:  # sqlite
    if not config.db.database_path_sqlite:
        raise ValueError("SQLITE_DB_PATH must be set when using SQLite")
    PROJECT_ROOT = Path(__file__).parent.parent
    DB_PATH = PROJECT_ROOT / config.db.database_path_sqlite
    DB_PATH.parent.mkdir(exist_ok=True)
    DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

if config.db.type == "postgresql":
    engine = create_async_engine(
        DATABASE_URL,
        echo=config.debug,
        pool_size=5,
        max_overflow=10,
    )
else:
    engine = create_async_engine(DATABASE_URL, echo=config.debug)

async_session_maker = async_sessionmaker(engine, expire_on_commit=False)


class Base(AsyncAttrs, DeclarativeBase):
    __abstract__ = True


async def get_session():
    async with async_session_maker() as session:
        yield session


async def init_db():
    # Import models to register them with Base.metadata
    from app.models.db import user  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
