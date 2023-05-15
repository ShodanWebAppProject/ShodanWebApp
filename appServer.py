#IDEA FROM: https://github.com/tutsplus/create-a-web-app-from-scratch-using-python-flask-and-mysql
from flask import Flask, render_template, redirect, request, session
from flask_session import Session
from flask_sock import Sock
import shodan
import requests

app = Flask(__name__)
sockVuln = Sock(app)
sock = Sock(app)

# Session
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@sockVuln.route('/vuln')
def echo(sockVuln):
    app.logger.info("Connection accepted")

    api = shodan.Shodan(session["shodanid"])

    target = sockVuln.receive()

    dnsResolve = f"https://api.shodan.io/dns/resolve?hostnames={target}&key={session['shodanid']}"
    print("Target: " + target)

    try:
        resolved = requests.get(dnsResolve)
        hostIP = resolved.json()[target]
        host = api.host(hostIP)
    except:
        print("Error in resolving IP")
        sockVuln.send("<br><h5><b>ERROR RESOLVING IP</b></h5>")
        return

    try:
        sockVuln.send("<br><h5><b>VULN</b></h5><br>")
        for item in host['vulns']:
            CVE = item.replace('!', '')
            sockVuln.send('<b>Vulns</b>: %s<br>' % item)
            exploits = api.exploits.search(CVE)
            for item in exploits['matches']:
                if item.get('cve')[0] == CVE:
                    sockVuln.send("<br><b>Description:</b><br>" + item.get('description') + "<br><br>")
        return
    except:
        print('An error occurred')
        sockVuln.send("<br><h5><b>ERROR IN REQUEST</b></h5>")

@app.route('/')
def main():
    if not session.get("shodanid"):
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
    api = shodan.Shodan(session["shodanid"])

    target = sock.receive()

    print("Target: " + target)

    try:
        host = api.host(target)
    except:
        print("Error in resolving IP")
        sock.send("<br><h5><b>ERROR RESOLVING IP</b></h5>")
        return

    try:
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
    