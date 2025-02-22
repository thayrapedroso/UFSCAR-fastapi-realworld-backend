import pytest
from httpx import AsyncClient
from conduit.app import app  # Certifique-se de que 'main' contém a instância do FastAPI
import pytest_asyncio


@pytest_asyncio.fixture()
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_create_user(client):
    response = await client.post(
        "/api/users",
        json={
            "user": {
                "username": "testuser",
                "email": "testuser@example.com",
                "password": "securepassword123"
            }
        }
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert "user" in data
    assert data["user"]["email"] == "testuser@example.com"


@pytest.mark.asyncio
async def test_login_user_invalid_credentials(client):
    response = await client.post(
        "/api/users/login",
        json={
            "user": {
                "email": "wrong@example.com",
                "password": "wrongpassword"
            }
        }
    )
    assert response.status_code == 400, response.text


@pytest.mark.asyncio
async def test_get_articles_unauthenticated(client):
    response = await client.get("/api/articles")
    assert response.status_code == 200, response.text
    assert "articles" in response.json()


@pytest.mark.asyncio
async def test_create_article_unauthorized(client):
    response = await client.post(
        "/api/articles",
        json={
            "article": {
                "title": "Unauthorized Test",
                "description": "Should fail",
                "body": "No auth provided"
            }
        }
    )
    assert response.status_code == 403, response.text  # Sem autenticação deve falhar


@pytest.mark.asyncio
async def test_get_profile_not_found(client):
    response = await client.get("/api/profiles/nonexistentuser")
    assert response.status_code == 404, response.text

# Casos de testes adicionados:
# - Criação de usuário (test_create_user) [ChatGPT-4.0]
# - Login com credenciais inválidas (test_login_user_invalid_credentials) [ChatGPT-4.0]
# - Consulta de artigos sem autenticação (test_get_articles_unauthenticated) [ChatGPT-4.0]
# - Tentativa de criação de artigo sem autenticação (test_create_article_unauthorized) [ChatGPT-3.5]
# - Busca de perfil inexistente (test_get_profile_not_found) [ChatGPT-3.5]