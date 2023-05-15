import pytest
from appServer import app as flask_app
from flask import Flask, render_template, json, redirect, request, session
from flask_session import Session
from flask_sock import Sock
import shodan
import requests

@pytest.fixture
def app():
    yield flask_app

@pytest.fixture
def client(app):
    return app.test_client()

def test_index(client):
    response = client.get("/login")

    assert response.status_code == 200

def test_session_key(client):
    with client.session_transaction() as session:
        session["shodanid"] = "example_key"

    response = client.get("/")
    assert response.status_code == 200
    assert session.get("shodanid") == "example_key"


def test_login(client):
    with client.session_transaction() as session:
        response = client.get("/login")
    assert session.get("shodanid") == None
