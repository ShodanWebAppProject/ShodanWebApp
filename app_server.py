#IDEA FROM: https://github.com/tutsplus/create-a-web-app-from-scratch-using-python-flask-and-mysql

'''app_service for shodan web app'''

from flask import Flask, render_template, redirect, request, session
from flask_session import Session
from flask_sock import Sock
import shodan
import requests

app = Flask(__name__)
sock_vuln = Sock(app)
sock = Sock(app)

# Session
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@sock_vuln.route('/vuln')
def echo(socket_vuln):
    '''Web-socket connection for obtain information about ip vuln'''

    app.logger.info("Connection accepted")

    api = shodan.Shodan(session["shodanid"])

    target = socket_vuln.receive()

    dns_resolve = f"https://api.shodan.io/dns/resolve?hostnames={target}&key={session['shodanid']}"
    print("Target: " + target)

    try:
        resolved = requests.get(dns_resolve,timeout=5)
        host_ip = resolved.json()[target]
        host = api.host(host_ip)
    except shodan.APIError :
        print("Error in resolving IP")
        socket_vuln.send("<br><h5><b>ERROR RESOLVING IP</b></h5>")
        return
    try:
        socket_vuln.send("<br><h5><b>VULN</b></h5><br>")
        for item in host['vulns']:
            cve = item.replace('!', '')
            socket_vuln.send('<b>Vulns</b>:'+item+'<br>')
            exploits = api.exploits.search(cve)
            for item in exploits['matches']:
                if item.get('cve')[0] == cve:
                    socket_vuln.send("<br><b>Description:</b><br>"+
                                    item.get('description')+"<br><br>")
        return
    except request.routing_exception:
        print('An error occurred')
        socket_vuln.send("<br><h5><b>ERROR IN ROUTING REQUEST</b></h5>")
    except shodan.APIError:
        print('An error occurred')
        socket_vuln.send("<br><h5><b>ERROR IN SHODAN REQUEST</b></h5>")

@app.route('/')
def main():
    '''index render'''
    if not session.get("shodanid"):
        return redirect("/login")
    return render_template('index.html')

@app.route("/logout")
def logout():
    '''Logout from session'''
    session["shodanid"] = None
    return redirect("/")

@app.route("/login", methods=["POST", "GET"])
def login():
    '''Session login'''
    if request.method == "POST":
        session["shodanid"] = request.form.get("shodanid")
        return redirect("/")
    return render_template("login.html")

@app.route('/getshodanid/')
def getshodanid():
    '''Request get for shodan ID'''
    return session["shodanid"]

def print_dict(list_dict):
    '''Print list of dictionary'''
    value_dict=""
    for dictionar in list_dict:
        for keys, value in dictionar.items():
            value_dict+="<b>"+keys+"</b>: "+str(value)+"<br>"
        value_dict+="<br>"
    return value_dict

@app.route('/getalert/')
def getalert():
    '''Request get for alert'''
    api = shodan.Shodan(session["shodanid"])
    list_alert=api.alerts()
    #return print_dict(list_alert)
    return list_alert

@app.route('/alarm')
def alarm():
    '''index alarm'''
    if not session.get("shodanid"):
        return redirect("/login")
    return render_template('alarm.html')

@app.route("/deletealarm", methods=["POST", "GET"])
def deletealarm():
    '''Delete alarm'''
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

@app.route("/createalarm", methods=["POST", "GET"])
def createalarm():
    '''Create alarm'''
    if request.method == "POST":
        args = request.json
        try:
            api = shodan.Shodan(session["shodanid"])
            print("alert:"+args["name"]+" "+args["ip"])
            if args["name"]=="":
                print(api.create_alert("alert:"+args["ip"],args["ip"]))
            else:
                print(api.create_alert(args["name"],args["ip"]))
            return "alarm created"
        except shodan.APIError:
            return str(shodan.APIError)+" error, alarm not created"
    return "error, alarm not created"


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
        socket_info.send("<b>IP</b>: "+host['ip_str']+"<br>")
        socket_info.send("<b>Organization</b>: "+host.get('org', 'n/a')+"<br>")
        socket_info.send("<b>Operating System</b>: "+host.get('os', 'n/a')+"<br>")
        return
    except request.routing_exception :
        print('An error occured')
        socket_info.send("<br><h5><b>ERROR IN REQUEST</b></h5>")
        #sock.close()
        return

if __name__ == "__main__":
    app.run()
    