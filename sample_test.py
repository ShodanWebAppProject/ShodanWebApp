import pytest
from appServer import app as flask_app
from flask import Flask, render_template, json, redirect, request, session

@pytest.fixture
def app():
    yield flask_app

@pytest.fixture
def client(app):
    return app.test_client()

def test_index(client):
    response = client.get("/login")

    assert response.status_code == 200
