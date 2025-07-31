import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.api.db.database import get_db, create_database, get_db_url

@pytest.mark.asyncio
async def test_create_tables():
    """
    Test if database tables can be created without error.
    """
    try:
        await create_database()
    except Exception as e:
        pytest.fail(f"Database creation failed: {e}")


@pytest.mark.asyncio
async def test_db_connection():
    """
    Ensure we can open and execute a basic query in a new DB session.
    """
    test_engine = create_async_engine(get_db_url(), echo=False)
    async_session = sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session() as session:
        assert isinstance(session, AsyncSession)
        result = await session.execute(text("SELECT 1"))
        assert result.scalar() == 1

    await test_engine.dispose()


@pytest.mark.asyncio
async def test_get_db_yields_session():
    """
    Test that a session created like get_db works in current test loop.
    """
    test_engine = create_async_engine(get_db_url(), echo=False)
    TestSessionLocal = sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def get_test_db():
        async with TestSessionLocal() as session:
            yield session

    # Get session from test generator
    gen = get_test_db()
    session = await gen.__anext__()

    assert isinstance(session, AsyncSession)

    result = await session.execute(text("SELECT 1"))
    assert result.scalar() == 1

    # Finish the generator
    try:
        await gen.__anext__()
    except StopAsyncIteration:
        pass

    await test_engine.dispose()