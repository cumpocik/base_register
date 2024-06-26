from django.test import TestCase
import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from .models import RevokedToken
from .views import create_jwt_token, verify_jwt_token
import hashlib

User = get_user_model()
client = Client()

@pytest.fixture
def user():
    user = User.objects.create_user(username='testuser', password='12345678QQ')
    return user

@pytest.fixture
def token(user):
    return create_jwt_token(user)

@pytest.mark.django_db
def test_user_creation(user):
    assert User.objects.count() == 1
    assert User.objects.get(username='testuser') == user

@pytest.mark.django_db
def test_jwt_token_creation(user, token):
    assert token is not None
    decoded_user = verify_jwt_token(token)
    assert decoded_user == user

@pytest.mark.django_db
def test_jwt_token_verification_failure():
    invalid_token = 'invalid.token.string'
    assert verify_jwt_token(invalid_token) is None

@pytest.mark.django_db
def test_revoke_token_view(user, token):
    client.cookies['jwt'] = token
    response = client.post('/revoke_token/')
    assert response.status_code == 200
    assert RevokedToken.objects.filter(token_hash=hashlib.sha256(token.encode('utf-8')).hexdigest()).exists()

@pytest.mark.django_db
def test_login_view_success(user):
    response = client.post('/login/', {'username': 'testuser', 'password': '12345678QQ'})
    assert response.status_code == 302
    assert response.cookies.get('jwt').value is not None

@pytest.mark.django_db
def test_login_view_failure():
    response = client.post('/login/', {'username': 'wronguser', 'password': 'wrongpass'})
    assert response.status_code == 200
    assert 'Неверное имя пользователя или пароль' in response.content.decode()
