from typing import Optional, Union
from pydantic import BaseModel

from app.api.v1.schemas.sucess_response import SuccessResponse


def success_response(
    status_code: int,
    message: str,
    data: Optional[Union[BaseModel, dict]] = None
) -> SuccessResponse:
    """
    Generate a standardized success response using the SuccessResponse schema.

    This function is designed to be returned directly from FastAPI route handlers.
    It ensures consistent API structure and integrates with OpenAPI documentation.

    Args:
        status_code (int): HTTP status code indicating the result of the operation.
        message (str): A descriptive message about the outcome.
        data (Optional[Union[BaseModel, dict]]): Optional payload to include in the response.
            Can be a Pydantic model or a dictionary.

    Returns:
        SuccessResponse: A structured response model containing the status code, message,
        success flag, and optional data payload.
    """
    return SuccessResponse(
        status_code=status_code,
        success=True,
        message=message,
        data=data
    )
