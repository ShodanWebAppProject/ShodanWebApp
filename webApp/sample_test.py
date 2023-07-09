'''pytest script'''

import pytest
import shodan
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

def test_shodanid_no_session(client):
    '''test shodan id'''
    response = client.get('/shodaid')
    assert response.status_code == 302

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

def test_get_shodan_id(client):
    '''test get shodan id'''
    with client.session_transaction() as session:
        session["shodanid"] = "example_key"
        session["user"] = "example_user"
    response = client.get("/getshodanid/")
    assert response.text == session["shodanid"]

def test_alarm(client):
    '''test get alert'''
    with client.session_transaction() as session:
        session["shodanid"] = "example_key"
        session["user"] = "example_user"
    response = client.get("/alarm")
    assert response.status_code == 200

def test_list_alert(client):
    '''test list alert'''
    with client.session_transaction() as session:
        session["shodanid"] = "W9YKu6EZhmfJEuzdu34weobtOf0WoSQC"
        session["user"] = "example_user"
    response = client.get("/getalert/")
    api = shodan.Shodan(session["shodanid"])
    list_alert=api.alerts()
    assert response.text == str(list_alert)+"\n"

def test_create_delete_alert(client):
    '''test create delete alert'''
    with client.session_transaction() as session:
        session["shodanid"] = "tJiMTHh65vvJsgg4AaBtRRMZ844LFPpV"
        session["user"] = "example_user"
    jsonvalue = {
        'ip' : '167.114.198.227',
        'name': 'test',
    }
    response = client.post('/createalarm',json = jsonvalue)
    print(response.text)
    jsonvalue = {
        'id' : response.text,
    }
    response = client.post('/deletealarm', json = jsonvalue)
    assert response.text == "alarm deleted"

def test_callback(client):
    url='https://dev-m2sie3j46ouu7opn.us.auth0.com/oauth/token'
    payload = {"client_id":"A41DU0dXZPtn6pqqgb2A49JUXSfYqTNc",
        "client_secret":"n0s3aS1MXVDjnGlU1HetFKfeEsnB687r2StKlLZwkmM-LgM3XPTvtuckfnozY-c1",
        "audience":"https://dev-m2sie3j46ouu7opn.us.auth0.com/api/v2/",
        "grant_type":"client_credentials"}
    res = client.post(url, data=payload)
    text=str(res.text)
    print(text)
    access_token=text.split(",", maxsplit=1)[0].split(":")[1].split('"')[1]
    with client.session_transaction() as session:
        session["access_token"] = access_token
        session["client_id"] = "W9YKu6EZhmfJEuzdu34weobtOf0WoSQC"
    
    urlget='https://dev-m2sie3j46ouu7opn.us.auth0.com/api/v2/users/'+session["client_id"]
    headerget={ 'authorization': 'Bearer '+ session["access_token"],
               'content-type':'application/json'} 
    resget = client.get(urlget, headers=headerget)
    print(str(resget.text))

    shodanid=str(resget.text).split('shodanID":')[1].split("}")[0]
    assert shodanid == "W9YKu6EZhmfJEuzdu34weobtOf0WoSQC"
