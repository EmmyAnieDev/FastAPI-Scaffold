from typing import Callable
from fastapi import Request
from fastapi.responses import JSONResponse


def create_exception_handler(status_code: int, message: str) -> Callable:
    """
    Factory function that returns an exception handler function.

    Args:
        status_code (int): The HTTP status code to return.
        message (str): The message to include in the response.

    Returns:
        Callable: An async function that handles exceptions and returns JSONResponse.
    """
    async def handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=status_code,
            content={
                "status_code": status_code,
                "success": False,
                "message": message,
                "data": None
            }
        )
    return handler