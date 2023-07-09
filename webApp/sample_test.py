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

def test_session_key(client):
    '''test app session'''
    with client.session_transaction() as session:
        session["shodanid"] = "example_key"
        session["user"] = "example_user"
    response = client.get("/")
    assert response.status_code == 200

def test_missing_session(client):
    '''test missing session'''
    response = client.get("/")
    assert response.status_code == 302

def test_missing_session_shodaid(client):
    '''test missing shodan'''
    with client.session_transaction() as session:
        session["shodanid"] = "example_key"
    response = client.get("/")
    assert response.status_code == 302
    session.clear()

def test_missing_session_user(client):
    '''test missing user'''
    with client.session_transaction() as session:
        session["user"] = "example_user"
    response = client.get("/")
    assert response.status_code == 302
    session.clear()

def test_login_redirect(client):
    '''test login redirect'''
    response = client.get("/login")
    assert response.status_code == 302
