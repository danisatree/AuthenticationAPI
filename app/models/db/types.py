from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.dialects import mysql, postgresql
from sqlalchemy.types import TypeDecorator


class TimestampNoMillis(TypeDecorator):
    impl = DateTime
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(postgresql.TIMESTAMP(precision=0))
        if dialect.name == "mysql":
            return dialect.type_descriptor(mysql.DATETIME(fsp=0))
        if dialect.name == "sqlite":
            return dialect.type_descriptor(String(19))
        return dialect.type_descriptor(DateTime())

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        value = value.replace(microsecond=0)
        if dialect.name == "sqlite":
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if dialect.name == "sqlite" and isinstance(value, str):
            if "." in value:
                value = value.split(".", 1)[0]
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        if isinstance(value, datetime):
            return value.replace(microsecond=0)
        return value
