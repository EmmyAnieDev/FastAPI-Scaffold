"""This is the Base Model Class"""
import enum
from datetime import datetime

from uuid6 import uuid7
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import Column, String, DateTime, delete as sqlalchemy_delete

from app.api.db.database import Base

class BaseTableModel(Base):
    __abstract__ = True

    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid7()))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            c.name: getattr(self, c.name).value if isinstance(getattr(self, c.name), enum.Enum) else getattr(self, c.name)
            for c in self.__table__.columns
        }

    async def save(self, session: AsyncSession):
        """Asynchronously add and commit the current instance to the database."""
        session.add(self)
        await session.commit()
        await session.refresh(self)
        return self

    async def delete(self, session: AsyncSession):
        """Asynchronously delete the current instance from the database."""
        await session.delete(self)
        await session.commit()

    @classmethod
    async def get_all(cls, session: AsyncSession):
        """Asynchronously retrieve all instances of the model."""
        result = await session.execute(select(cls))
        return result.scalars().all()

    @classmethod
    async def get_by_id(cls, id: str, session: AsyncSession):
        """Asynchronously retrieve an instance by ID."""
        result = await session.execute(select(cls).where(cls.id == id))
        return result.scalars().first()
