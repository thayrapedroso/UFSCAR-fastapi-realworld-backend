import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from conduit.core.security import verify_password
from conduit.infrastructure.repositories.user import UserRepository


@pytest.mark.anyio
async def test_user_success_registration(
    test_client: AsyncClient, session: AsyncSession, user_repository: UserRepository
) -> None:
    email, username, password = ("success@gmail.com", "success", "password")
    payload = {"user": {"email": email, "username": username, "password": password}}
    response = await test_client.post("/users", json=payload)
    assert response.status_code == 200

    user = await user_repository.get_by_email(session=session, email=email)
    assert user.email == email
    assert user.username == username
    assert verify_password(plain_password=password, hashed_password=user.password_hash)


@pytest.mark.parametrize(
    "field, value", (("username", "new_username"), ("email", "new-email@gmail.com"))
)
@pytest.mark.anyio
async def test_user_registration_with_taken_credentials(
    test_client: AsyncClient, field: str, value: str
) -> None:
    payload = {
        "user": {
            "email": "success@gmail.com",
            "username": "success",
            "password": "password",
        }
    }
    payload["user"][field] = value
    response = await test_client.post("/users", json=payload)
    assert response.status_code == 400
