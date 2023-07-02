from functools import wraps
import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
from urllib.request import urlopen

import mysql.connector as db
import sys

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, request, jsonify,_request_ctx_stack, g
import requests

from jose import jwt

import http.client

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)


AUTH0_DOMAIN = env.get("AUTH0_DOMAIN")
AUTH0_AUDIENCE = env.get("AUTH0_AUDIENCE")
ALGORITHMS = ["RS256"]


# DB setting
if len(sys.argv)<2:
    databaseSQL="test_mqtt"
else:
    databaseSQL = sys.argv[1] # test_mqtt
if len(sys.argv)<3:
    ipSQL = "mysql"
else:
    ipSQL = sys.argv[2] #mysql
if len(sys.argv)<4:
    portSQL = "3308"
else:
    portSQL = sys.argv[3] # 3308
if len(sys.argv)<5:
    userSQL = "root"
else:
    userSQL = sys.argv[4] # root
if len(sys.argv)<6:
    passwordSQL = "password"
else:
    passwordSQL = sys.argv[5] # password



app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

# Error handler
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

def get_token_auth_header():
    """Obtains the Access Token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                        "description":
                            "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must start with"
                            " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                        "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Authorization header must be"
                            " Bearer token"}, 401)

    token = parts[1]
    return token

def requires_scope(required_scope: str) -> bool:
    """Determines if the required scope is present in the access token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scope"):
        token_scopes = unverified_claims["scope"].split()
        for token_scope in token_scopes:
            if token_scope == required_scope:
                return True
    return False

def requires_auth(f):
    """Determines if the Access Token is valid
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=AUTH0_AUDIENCE,
                    issuer="https://"+AUTH0_DOMAIN+"/"
                )
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                "description":
                                    "incorrect claims,"
                                    "please check the audience and issuer"}, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                "description":
                                    "Unable to parse authentication"
                                    " token."}, 401)

            _request_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                        "description": "Unable to find appropriate key"}, 401)
    return decorated

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

def get_token_auth_header():
    """Obtains the access token from the Authorization Header."""
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({
            "code": "authorization_header_missing",
            "description": "Authorization header is expected"
        }, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({
            "code": "invalid_header",
            "description": "Authorization header must start with Bearer"
        }, 401)
    elif len(parts) == 1:
        raise AuthError({
            "code": "invalid_header",
            "description": "Token not found"
        }, 401)
    elif len(parts) > 2:
        raise AuthError({
            "code": "invalid_header",
            "description": "Authorization header must be Bearer token"
        }, 401)
    token = parts[1]
    return token

def requires_auth(f):
    """Determines if the access token is valid."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError:
            raise AuthError({"code": "invalid_header",
                             "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
        if unverified_header["alg"] == "HS256":
            raise AuthError({"code": "invalid_header",
                             "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=AUTH0_AUDIENCE,
                    issuer="https://" + AUTH0_DOMAIN + "/"
                )
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                 "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                 "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                 "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)
            g.auth = payload
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 401)
    return decorated


# Controllers API
@app.route("/")
def home():
    value=""
    dbdatatext=""
    if session.get("Authorization"):
        #app.logger.debug("session authorization: "+(session.get("Authorization")))
        headers = {'Authorization': session.get("Authorization")}
        result=requests.get("http://localhost:3000/validate", headers=headers)
        app.logger.debug(str(result.text))
        value=result.text

        headers = {'Authorization': session.get("Authorization")}
        dbdata=requests.get("http://localhost:3000/getdb", headers=headers)
        dbdatatext=dbdata.text
    else:
        app.logger.debug( "Non hai le autorizzazioni")


    return render_template(
        "home.html",
        session=session.get("user"),
        prettyUser=json.dumps(session.get("user"), indent=4),
        prettyAuth=json.dumps(value, indent=4),
        dbvalue=dbdatatext,
    )

@app.route("/callback")
def callback():

    # Get token login
    token = oauth.auth0.authorize_access_token()
    session["user"] = token

    # Get access token
    url='https://dev-l2gdfi4a5eo6in0i.us.auth0.com/oauth/token'
    payload = { 'grant_type': "client_credentials",'client_id':"W322SgZMDtl76hUBdZ3k6BlinV1tT82R",'client_secret':"fVo0xEHciNuIE5fauRrBFDgDmHwVMLplReaUY1s2HbzQPAeltuwGySxIXnuX3TPn",'audience':"https://testloginistio.io"}
    headers = { 'content-type': "application/x-www-form-urlencoded" }
    res = requests.post(url, data=payload, headers=headers)
    text=str(res.text)
    access_token=text.split(",")[0].split(":")[1].split('"')[1]
    session["Authorization"] = 'Bearer '+access_token

    return redirect("/")


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )   



@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


@app.route('/validate', methods=['GET','POST'])
@requires_auth
def validate():
    return jsonify(g.auth)

@app.route('/getdb/')
def getdb():
    app.logger.debug("get value from DB")
    db_connection = db.connect(host=ipSQL, user=userSQL, password=passwordSQL, port=portSQL, database=databaseSQL)
    cursor = db_connection.cursor()
    '''Request get for db information'''
    sql = "SELECT * FROM test_mqtt.messagemqtt"
    myresult=""
    printvalue=""
    try:
        cursor.execute(sql)
        myresult = cursor.fetchall()
        for row in myresult:
            printvalue+="<tr><td>"+row[0]+"</td><td>"+row[1]+"</td></tr>"
    except db.Error as error:
        printvalue="Error: {}".format(error)

    #print("value: "+printvalue)
    db_connection.close()
    return printvalue


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=env.get("PORT", 3000))
