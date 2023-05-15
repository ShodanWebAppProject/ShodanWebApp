#IDEA FROM: https://github.com/tutsplus/create-a-web-app-from-scratch-using-python-flask-and-mysql

# This WebSocket implementation is compatible with the Flask development web server.
# For a production deployment it can be used with Gunicorn, Eventlet or Gevent.

from flask import Flask, render_template, json, redirect, request, session
from flask_session import Session
from flask_sock import Sock
import shodan
import requests



app = Flask(__name__)

# Socket
sockVuln = Sock(app)
sock= Sock(app)

# Session
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@sockVuln.route('/vuln')
def echo(sockVuln):
    app.logger.info("Connection accepted")

    # SHODAN_API_KEY = "W9YKu6EZhmfJEuzdu34weobtOf0WoSQC" 
    api = shodan.Shodan(session["shodanid"])
    # target = '167.114.198.227'
   

    target = sockVuln.receive()

    # print(session["shodanid"])


    dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + session["shodanid"]
    print("Target: "+target)
    
    try:
        # First we need to resolve our targets domain to an IP
        resolved = requests.get(dnsResolve)
        hostIP = resolved.json()[target]
       
        # Then we need to do a Shodan search on that IP
        host = api.host(hostIP)
    except:
        print("Error in resolution IP")
        sockVuln.send("<br><h5><b>ERROR RESOLUTION IP</b></h5>")
        #sock.close()
        return

    try:     

        #print("---------------IP INFORMATION---------------")
        # sockVuln.send("<br><h5><b>IP INFORMATION</b></h5><br>")
        # sockVuln.send("<b>IP</b>: %s<br>" % host['ip_str'])
        # sockVuln.send("<b>Organization</b>: %s<br>" % host.get('org', 'n/a'))
        # sockVuln.send("<b>Operating System</b>: %s<br>" % host.get('os', 'n/a'))

        # Print vuln information
        sockVuln.send("<br><h5><b>VULN</b></h5><br>")
        for item in host['vulns']:
            CVE = item.replace('!','')
            sockVuln.send('<b>Vulns</b>: %s<br>' % item)
            exploits = api.exploits.search(CVE)
            for item in exploits['matches']:
                if item.get('cve')[0] == CVE:
                    sockVuln.send("<br><b>Desciption:</b><br>"+item.get('description')+"<br><br>")

        # sock.close()
        return
    except: 
        print('An error occured')
        sockVuln.send("<br><h5><b>ERROR IN REQUEST</b></h5>")
        #sock.close()
        return


@app.route('/')
def main():
    # check if the users exist or not
    if not session.get("shodanid"):
        # if not there in the session then redirect to the login page
        return redirect("/login")
    return render_template('index.html')

@app.route("/logout")
def logout():
    session["shodanid"] = None
    return redirect("/")

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        session["shodanid"] = request.form.get("shodanid")
        return redirect("/")
    return render_template("login.html")

@app.route('/getshodanid/')
def getshodanid():
    return session["shodanid"]

@sock.route('/gethostinfo')
def getshostinfo(sock):
    # SHODAN_API_KEY = "W9YKu6EZhmfJEuzdu34weobtOf0WoSQC" 
    api = shodan.Shodan(session["shodanid"])
    # target = '167.114.198.227'

    target = sock.receive()
    # print(session["shodanid"])

    #dnsResolve = 'https://api.shodan.io/shodan/host/'+target+'?key='+session["shodanid"]

    print("Target: "+target)
    
    try:
        # First we need to resolve our targets domain to an IP
        # resolved = requests.get(dnsResolve)

        # hostIP = resolved.json()[target]
        print(target)
        # Then we need to do a Shodan search on that IP
        host = api.host(target)
    except:
        print("Error in resolution IP")
        sock.send("<br><h5><b>ERROR RESOLUTION IP</b></h5>")
        #sock.close()
        return

    try:     
        #print("---------------IP INFORMATION---------------")
        sock.send("<br><h5><b>IP INFORMATION</b></h5><br>")
        sock.send("<b>IP</b>: %s<br>" % host['ip_str'])
        sock.send("<b>Organization</b>: %s<br>" % host.get('org', 'n/a'))
        sock.send("<b>Operating System</b>: %s<br>" % host.get('os', 'n/a'))
        return
    except: 
        print('An error occured')
        sock.send("<br><h5><b>ERROR IN REQUEST</b></h5>")
        #sock.close()
        return

if __name__ == "__main__":
    app.run()
    