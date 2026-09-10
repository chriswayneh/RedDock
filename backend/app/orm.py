"""Configuration-free SQLAlchemy metadata shared by runtime and offline tools."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
