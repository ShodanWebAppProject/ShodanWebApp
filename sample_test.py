'''pytest script'''

import pytest
from app_server import app as flask_app

@pytest.fixture
def app():
    '''fixture app'''
    yield flask_app

@pytest.fixture
def client(application):
    '''fixture client'''
    return application.test_client()

def test_index(client_user):
    '''test app index'''
    response = client_user.get("/login")
    assert response.status_code == 200

def test_session_key(client_user):
    '''test app session'''
    with client_user.session_transaction() as session:
        session["shodanid"] = "example_key"

    response = client_user.get("/")
    assert response.status_code == 200
    with client_user.session_transaction() as session:
        assert session.get("shodanid") == "example_key"


def test_login(client_user):
    '''test app login'''
    with client_user.session_transaction() as session:
        response = client_user.get("/login")
        assert response.status_code == 200
        assert session.get("shodanid") is None
