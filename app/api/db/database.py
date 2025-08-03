from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.ext.declarative import declared_attr
from config import BASE_DIR, settings

DB_HOST = settings.DB_HOST
DB_PORT = settings.DB_PORT
POSTGRES_USER = settings.POSTGRES_USER
POSTGRES_PASSWORD = settings.POSTGRES_PASSWORD
POSTGRES_DB = settings.POSTGRES_DB
DB_TYPE = settings.DB_TYPE

Base = declarative_base()


def get_db_url(test_mode: bool = False) -> str:
    """
    Constructs and returns the database URL for asynchronous SQLAlchemy engines.

    Args:
        test_mode (bool): If True, use a test database configuration.

    Returns:
        str: A fully qualified async database URL.
    """

    # If using SQLite or in test mode, construct SQLite URL
    if DB_TYPE == "sqlite" or test_mode:
        # Use "test.db" for test mode, otherwise "db.sqlite3"
        db_file = "test.db" if test_mode else "db.sqlite3"
        # Use 'sqlite+aiosqlite' driver for async SQLite support
        return f"sqlite+aiosqlite:///{BASE_DIR}/{db_file}"

    # If using PostgreSQL, build the connection string using asyncpg driver
    elif DB_TYPE == "postgresql":
        return (
            f"postgresql+asyncpg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@"
            f"{DB_HOST}:{DB_PORT}/{POSTGRES_DB}"
        )

    # Default fallback to SQLite with async driver if DB_TYPE is unrecognized
    return f"sqlite+aiosqlite:///{BASE_DIR}/db.sqlite3"


DATABASE_URL = get_db_url()

# Async engine
engine = create_async_engine(DATABASE_URL, echo=True)

# Async session
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# Dependency to be used in routes
async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# Optional: Create DB tables at startup (async)
async def create_database():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
