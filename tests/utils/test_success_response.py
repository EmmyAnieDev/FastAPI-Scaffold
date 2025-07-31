import pytest
from pydantic import BaseModel

from app.api.utils.success_response import success_response
from app.api.v1.schemas.sucess_response import SuccessResponse

# Example Pydantic model for testing
class SampleData(BaseModel):
    name: str
    age: int

def test_success_response_with_dict():
    response = success_response(
        status_code=200,
        message="Data fetched successfully",
        data={"key": "value"}
    )

    assert isinstance(response, SuccessResponse)
    assert response.status_code == 200
    assert response.success is True
    assert response.message == "Data fetched successfully"
    assert response.data == {"key": "value"}

def test_success_response_with_pydantic_model():
    data_model = SampleData(name="Alice", age=30)

    response = success_response(
        status_code=201,
        message="User created",
        data=data_model
    )

    assert isinstance(response, SuccessResponse)
    assert response.status_code == 201
    assert response.success is True
    assert response.message == "User created"
    assert response.data.dict() == data_model.dict()

def test_success_response_with_none_data():
    response = success_response(
        status_code=204,
        message="No content",
        data=None
    )

    assert isinstance(response, SuccessResponse)
    assert response.status_code == 204
    assert response.success is True
    assert response.message == "No content"
    assert response.data is None
