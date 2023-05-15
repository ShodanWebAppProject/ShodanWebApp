# content of test_sysexit.py
import pytest

from flask import Flask
from appServer import app # Flask instance of the API
import json


def test_index_route():

    response = app.test_client().get('/')

    assert response.status_code == 200