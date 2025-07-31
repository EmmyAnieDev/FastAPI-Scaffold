from sqlalchemy import Column, String
from sqlalchemy.orm import validates
from app.api.v1.models.base import BaseTableModel


class User(BaseTableModel):
    __tablename__ = "users"

    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)

    @validates("email")
    def validate_email(self, key, value):
        assert "@" in value, "Invalid email format"
        return value
