'''pytest script'''

import pytest
from app_server import app as flask_app

@pytest.fixture(name="app")
def app_fixture():
    '''fixture app'''
    yield flask_app

@pytest.fixture(name="client")
def client_fixture(app):
    '''fixture client'''
    return app.test_client()

def test_index(client):
    '''test app index'''
    response = client.get("/")
    assert response.status_code == 200

def test_session_key(client):
    '''test app session'''
    with client.session_transaction() as session:
        session["shodanid"] = "example_key"

    response = client.get("/")
    assert response.status_code == 200
    with client.session_transaction() as session:
        assert session.get("shodanid") == "example_key"


def test_login(client):
    '''test app login'''
    with client.session_transaction() as session:
        response = client.get("/")
        assert response.status_code == 200
        assert session.get("shodanid") is None
