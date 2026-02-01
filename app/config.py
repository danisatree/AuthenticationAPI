from dataclasses import dataclass
from pathlib import Path

from environs import Env


@dataclass
class JWTConfig:
    secret_key: str
    algorithm: str
    access_token_expire_minutes: int
    refresh_token_expire_days: int


@dataclass
class DataBaseConfig:
    type: str  # "sqlite" or "postgresql"
    database_path_sqlite: str | None = None
    postgresql_url: str | None = None


@dataclass
class Config:
    jwt: JWTConfig
    db: DataBaseConfig
    secret_key: str
    debug: bool


def load_config(path: str | None = None) -> Config:
    env = Env()

    # If no path provided, look for .env in project root
    if path is None:
        # Find project root (where .env should be)
        # In this new structure, helper is in app/config.py, so root is parent.parent
        project_root = Path(__file__).parent.parent
        env_path = project_root / ".env"
        if env_path.exists():
            env.read_env(str(env_path), override=True)
        else:
            # Fall back to reading from current directory or environment
            env.read_env()
    else:
        env.read_env(path, override=True)

    db_type = env.str("DATABASE_TYPE", "sqlite")

    return Config(
        jwt=JWTConfig(
            secret_key=env.str("JWT_SECRET_KEY"),
            algorithm=env.str("JWT_ALGORITHM", "HS256"),
            access_token_expire_minutes=env.int("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 30),
            refresh_token_expire_days=env.int("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7),
        ),
        db=DataBaseConfig(
            type=db_type,
            database_path_sqlite=(env.str("SQLITE_DB_PATH", "auth.db") if db_type == "sqlite" else None),
            postgresql_url=(env.str("DATABASE_URL", None) if db_type == "postgresql" else None),
        ),
        secret_key=env("SECRET_KEY"),
        debug=env.bool("DEBUG", default=False),
    )
