#IDEA FROM: https://github.com/tutsplus/create-a-web-app-from-scratch-using-python-flask-and-mysql

'''app_service for shodan web app'''

from authlib.integrations.flask_client import OAuth
from os import environ as env
from flask import Flask,redirect,render_template,session,url_for,request

from flask_session import Session
from flask_sock import Sock
import shodan
import requests

from urllib.parse import quote_plus, urlencode


from dotenv import find_dotenv, load_dotenv


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)


AUTH0_DOMAIN = env.get("AUTH0_DOMAIN")
AUTH0_AUDIENCE = env.get("AUTH0_AUDIENCE")
ALGORITHMS = ["RS256"]


app = Flask(__name__)
sock_vuln = Sock(app)
sock = Sock(app)
app.secret_key = "siufhjdipoofp"


# Session
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    connection="email",
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)


@sock_vuln.route('/vuln')
def echo(socket_vuln):
    '''Web-socket connection for obtain information about ip vuln'''

    #app.logger.info("Connection accepted")

    api = shodan.Shodan(session["shodanid"])

    target = socket_vuln.receive()

    #print(session['shodanid'])
    #dns_resolve = "https://api.shodan.io/dns/resolve?hostnames="+target+"&key="+session['shodanid']
    print("Target: " + target)
    try:
        #resolved = requests.get(dns_resolve)
        #print("resolved: "+str(resolved.text))
        #host_ip = resolved.json()[target]
        #print(host_ip)
        host = api.host(target)
    except shodan.APIError :
        print("Error in resolving IP")
        socket_vuln.send("<br><h5><b>ERROR RESOLVING IP</b></h5>")
        return
    try:
        socket_vuln.send("<br><h5><b>VULN</b></h5><br>")
        if 'vulns' in host:
            for item in host['vulns']:
                cve = item.replace('!', '')
                socket_vuln.send('<b>Vulns</b>:'+item+'<br>')
                exploits = api.exploits.search(cve)
                for item in exploits['matches']:
                    if item.get('cve')[0] == cve:
                        socket_vuln.send("<br><b>Description:</b><br>"+
                                        item.get('description')+"<br><br>")
        else:
            socket_vuln.send("<br><b>Vuln not found</b><br>")
        return
    except shodan.APIError:
        print('An error occurred')
        socket_vuln.send("<br><h5><b>ERROR IN SHODAN REQUEST</b></h5>")

@app.route('/')
def main():
    '''index render'''
    if not session.get("user"):
        return redirect("/login")
    if not session.get("shodanid"):
        return redirect("/shodaid")
    #print(session.get("user"))
    #print(session.get("shodanid"))
    return render_template('index.html')

@app.route('/shodaid', methods=["POST", "GET"])
def shodaid():
    '''index render'''
    if not session.get("user"):
        return redirect("/login")
    if request.method == "POST":
        session["shodanid"] = request.form.get("shodanid")

        url='https://dev-m2sie3j46ouu7opn.us.auth0.com/api/v2/users/'+session["client_id"]
        headers = {'Authorization': 'Bearer '+session["access_token"], 
                   'Content-Type':'application/json'}
        #print("'"+session["access_token"]+"'")
        #payload = {"user_metadata": {"shodanID": "'"+session["access_token"]+"'"}}
        payload = "{\"user_metadata\": {\"shodanID\": \""+session["shodanid"]+"\"}}"

        requests.patch(url, data=payload, headers=headers, timeout=5)

        return redirect("/")
    return render_template('shodanid.html')


@app.route("/logout")
def logout():
    '''Logout from session'''
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("main", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

@app.route("/login", methods=["POST", "GET"])
def login():
    '''Session login'''
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    '''callback'''
    token = oauth.auth0.authorize_access_token()
    texttoken=str(token)
    client_id=texttoken.split("'sub': '")[1].split("'")[0]
    session["client_id"] = client_id
    url='https://dev-m2sie3j46ouu7opn.us.auth0.com/oauth/token'
    payload = {"client_id":"A41DU0dXZPtn6pqqgb2A49JUXSfYqTNc",
               "client_secret":"n0s3aS1MXVDjnGlU1HetFKfeEsnB687r2StKlLZwkmM-LgM3XPTvtuckfnozY-c1",
               "audience":"https://dev-m2sie3j46ouu7opn.us.auth0.com/api/v2/","grant_type":"client_credentials"}
    res = requests.post(url, data=payload, timeout=5)
    text=str(res.text)
    access_token=text.split(",")[0].split(":")[1].split('"')[1]
    session["access_token"] = access_token
    session["user"] = token
    urlget= 'https://dev-m2sie3j46ouu7opn.us.auth0.com/api/v2/users/'+session["client_id"]
    headerget={ 'authorization': 'Bearer '+ session["access_token"],'content-type':'application/json'} 
    resget = requests.get(urlget, headers=headerget, timeout=5)
    print(str(resget.text))
    try:
        shodanid=str(resget.text).split('shodanID":')[1].split("}")[0]
        print("shodanID: "+shodanid)
        session['shodanid']=shodaid
    except IndexError as e:
        print("shodanid da inserire: "+e)
    return redirect("/")

@app.route('/getshodanid/')
def getshodanid():
    '''Request get for shodan ID'''
    if session.get("user") and session.get("shodanid"):  
        return session["shodanid"]
    print("not present a user session")
    return redirect("/login")

def print_dict(list_dict):
    '''Print list of dictionary'''
    value_dict=""
    for dictionar in list_dict:
        for keys, value in dictionar.items():
            value_dict+="<b>"+keys+"</b>: "+str(value)+"<br>"
        value_dict+="<br>"
    return value_dict

@app.route('/getplan/')
def getplan():
    '''Request get for plan key'''
    if session.get("user") and session.get("shodanid"):
        api = shodan.Shodan(session["shodanid"])
        plan = api.info()['plan']
        print("plan: "+plan)
        return plan
    print("not present a user session")
    return redirect("/login")

@app.route('/getalert/')
def getalert():
    '''Request get for alert'''
    if session.get("user") and session.get("shodanid"):
        api = shodan.Shodan(session["shodanid"])
        list_alert=api.alerts()
        #return print_dict(list_alert)
        return list_alert
    print("not present a user session")
    return redirect("/login")

@app.route('/alarm')
def alarm():
    '''index alarm'''
    if not session.get("user") and session.get("shodanid"):
        print("not present a user session")
        return redirect("/login")
    return render_template('alarm.html')

@app.route("/deletealarm", methods=["POST", "GET"])
def deletealarm():
    '''Delete alarm'''
    if session.get("user") and session.get("shodanid"):
        if request.method == "POST":
            args = request.json
            print(args["id"])
            try:
                api = shodan.Shodan(session["shodanid"])
                print(api.delete_alert(args["id"]))
                return "alarm deleted"
            except shodan.APIError:
                return "error, alarm not deleted"
        return "error, alarm not deleted"
    print("not present a user session")
    return redirect("/login")

def alert_enable_trigger(alert_id):
    """Enable a trigger for the alert"""
    # Get the list
    api = shodan.Shodan(session["shodanid"])
    try:
        api.enable_alert_trigger(alert_id, "new_service")
        api.enable_alert_trigger(alert_id, "malware")
        api.enable_alert_trigger(alert_id, "vulnerable")
    except Exception as exc:
        raise shodan.APIError from exc
    # We recommend enabling the triggers:
    # new_service
    # malware
    # open_database
    # iot
    # vulnerable
    # ssl_expired
    # industrial_control_system
    # internet_scanner

@app.route("/createalarm", methods=["POST", "GET"])
def createalarm():
    '''Create alarm'''
    if session.get("user") and session.get("shodanid"):
        if request.method == "POST":
            args = request.json
            try:
                api = shodan.Shodan(session["shodanid"])
                print("alert:"+args["name"]+" "+args["ip"])
                if args["name"]=="":
                    alarm_dict=api.create_alert("alert:"+args["ip"],args["ip"])
                    print(alarm_dict)
                else:
                    alarm_dict=api.create_alert(args["name"],args["ip"])
                    print(alarm_dict)
                alert_enable_trigger(alarm_dict['id'])
                return "alarm created"
            except shodan.APIError:
                return str(shodan.APIError)+" error, alarm not created"
        return "error, alarm not created"
    print("not present a user session")
    return redirect("/login")
        


@sock.route('/gethostinfo')
def getshostinfo(socket_info):
    '''Web-socket connection for obtain information about ip info'''
    api = shodan.Shodan(session["shodanid"])

    target = socket_info.receive()

    print("Target: " + target)

    try:
        host = api.host(target)
    except shodan.APIError:
        print("Error in resolving IP")
        socket_info.send("<br><h5><b>ERROR RESOLVING IP</b></h5>")
        return

    try:
        socket_info.send("<br><h5><b>IP INFORMATION</b></h5><br>")
        try:
            if host['ip_str'] is not None:
                socket_info.send("<b>IP</b>: "+host['ip_str']+"<br>")
        except shodan.APIError:
            print("Not find ip string")
        try:
            if host.get('org', 'n/a') is not None:
                socket_info.send("<b>Organization</b>: "+host.get('org', 'n/a')+"<br>")
        except shodan.APIError:
            print("Not find organization")
        try:
            if host.get('os', 'n/a') is not None:
                socket_info.send("<b>Operating System</b>: "+host.get('os', 'n/a')+"<br>")
        except shodan.APIError:
            print("Not find os")
        return
    except request.routing_exception as e_routing:
        print(e_routing.code+':An error occured')
        socket_info.send("<br><h5><b>ERROR IN REQUEST</b></h5>")
        #sock.close()
        return

if __name__ == "__main__":
    app.run()
    