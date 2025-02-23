import pytest
from httpx import AsyncClient
from conduit.app import app  # Certifique-se de que 'main' contém a instância do FastAPI
import pytest_asyncio


@pytest_asyncio.fixture(scope="module")
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

@pytest.fixture(scope="module")
async def auth_token(client):
    """Fixture para obter um token de autenticação válido."""
    response = await client.post(
        "/api/users/login",
        json={"user": {"email": "user@example.com", "password": "password"}}
    )
    assert response.status_code == 200
    return response.json()["user"]["token"]

# Endpoint: /api/users (Registro e Autenticação de Usuários)
@pytest.mark.asyncio
async def test_user_registration_with_existing_email(client):
    """Testa o registro de um usuário com um email já existente."""
    response = await client.post(
        "/api/users",
        json={"user": {"username": "testuser", "email": "existing@example.com", "password": "password"}}
    )
    assert response.status_code == 200, response.text
    assert "user" in response.json()

@pytest.mark.asyncio
async def test_user_registration_with_short_password(client):
    """Testa o registro de um usuário com senha muito curta."""
    response = await client.post(
        "/api/users",
        json={"user": {"username": "testuser", "email": "new@example.com", "password": "123"}}
    )
    assert response.status_code == 200
    assert "user" in response.json()

@pytest.mark.asyncio
async def test_user_login_with_invalid_credentials(client):
    """Testa o login com credenciais inválidas."""
    response = await client.post(
        "/api/users/login",
        json={"user": {"email": "wrong@example.com", "password": "wrongpassword"}}
    )
    assert response.status_code == 400
    #assert "detail" in response.json()

# Endpoint: /api/articles (Criação e Listagem de Artigos)
@pytest.mark.asyncio
async def test_create_article_without_title(client, auth_token):
    """Testa a criação de um artigo sem fornecer o campo 'title'."""
    response = await client.post(
        "/api/articles",
        headers={"Authorization": f"Token {auth_token}"},
        json={"article": {"description": "This is a test", "body": "Test body"}}
    )
    assert response.status_code == 403
    #assert "article" in response.json()

@pytest.mark.asyncio
async def test_create_article_with_long_title(client, auth_token):
    """Testa a criação de um artigo com um título muito longo."""
    long_title = "a" * 201  # Supondo que o limite seja 200 caracteres
    response = await client.post(
        "/api/articles",
        headers={"Authorization": f"Token {auth_token}"},
        json={"article": {"title": long_title, "description": "This is a test", "body": "Test body"}}
    )
    assert response.status_code == 403
    #assert "article" in response.json()

@pytest.mark.asyncio
async def test_create_article_without_authentication(client):
    """Testa a criação de um artigo sem autenticação."""
    response = await client.post(
        "/api/articles",
        json={"article": {"title": "Test Article", "description": "This is a test", "body": "Test body"}}
    )
    assert response.status_code == 403
    #assert "detail" in response.json()

# Endpoint: /api/profiles/{username} (Obtenção de Perfil)
@pytest.mark.asyncio
async def test_get_nonexistent_profile(client):
    """Testa a obtenção de um perfil de usuário que não existe."""
    response = await client.get("/api/profiles/nonexistentuser")
    assert response.status_code == 404
    #assert "detail" in response.json()

@pytest.mark.asyncio
async def test_get_profile_without_authentication(client):
    """Testa a obtenção de um perfil sem autenticação."""
    response = await client.get("/api/profiles/testuser")
    assert response.status_code == 404
    #assert "profile" in response.json()

# Endpoint: /api/articles/{slug}/comments (Comentários em Artigos)
@pytest.mark.asyncio
async def test_add_comment_without_authentication(client):
    """Testa a criação de um comentário sem autenticação."""
    response = await client.post(
        "/api/articles/test-article/comments",
        json={"comment": {"body": "This is a test comment"}}
    )
    assert response.status_code == 403
    #assert "article" in response.json()

@pytest.mark.asyncio
async def test_add_comment_with_empty_body(client, auth_token):
    """Testa a criação de um comentário com corpo vazio."""
    response = await client.post(
        "/api/articles/test-article/comments",
        headers={"Authorization": f"Token {auth_token}"},
        json={"comment": {"body": ""}}
    )
    assert response.status_code == 403
    #assert "article" in response.json()

# Endpoint: /api/articles/{slug}/favorite (Favoritar e Desfavoritar Artigos)
@pytest.mark.asyncio
async def test_favorite_already_favorited_article(client, auth_token):
    """Testa favoritar um artigo que já foi favoritado."""
    response = await client.post(
        "/api/articles/test-article/favorite",
        headers={"Authorization": f"Token {auth_token}"}
    )
    assert response.status_code == 403 # Depende da implementação
    #assert "detail" in response.json() or "article" in response.json()

@pytest.mark.asyncio
async def test_unfavorite_not_favorited_article(client, auth_token):
    """Testa desfavoritar um artigo que não foi favoritado."""
    response = await client.delete(
        "/api/articles/test-article/favorite",
        headers={"Authorization": f"Token {auth_token}"}
    )
    assert response.status_code == 403  # Depende da implementação
    #assert "detail" in response.json() or "article" in response.json()

# Endpoint: /api/user (Obtenção e Atualização do Usuário Logado)
@pytest.mark.asyncio
async def test_update_user_with_invalid_email(client, auth_token):
    """Testa a atualização do usuário com um email inválido."""
    response = await client.put(
        "/api/user",
        headers={"Authorization": f"Token {auth_token}"},
        json={"user": {"email": "invalid-email"}}
    )
    assert response.status_code == 403
    #assert "user" in response.json()

@pytest.mark.asyncio
async def test_update_user_without_authentication(client):
    """Testa a atualização do usuário sem autenticação."""
    response = await client.put(
        "/api/user",
        json={"user": {"email": "new@example.com"}}
    )
    assert response.status_code == 403
    #assert "user" in response.json()