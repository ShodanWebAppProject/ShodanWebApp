#IDEA FROM: https://github.com/tutsplus/create-a-web-app-from-scratch-using-python-flask-and-mysql

from flask import Flask, render_template, json, request, session

from flask_sock import Sock
import shodan
import requests



app = Flask(__name__)
sock = Sock(app)

@sock.route('/vuln')
def echo(sock):
    app.logger.info("Connection accepted")

    SHODAN_API_KEY = "W9YKu6EZhmfJEuzdu34weobtOf0WoSQC" 
    api = shodan.Shodan(SHODAN_API_KEY)
    # target = '167.114.198.227'
   

    target = sock.receive()


    dnsResolve = 'https://api.shodan.io/dns/resolve?hostnames=' + target + '&key=' + SHODAN_API_KEY
    print("Target: "+target)
    try:
        # First we need to resolve our targets domain to an IP
        resolved = requests.get(dnsResolve)
        hostIP = resolved.json()[target]

        # Then we need to do a Shodan search on that IP
        host = api.host(hostIP)

        #print("---------------IP INFORMATION---------------")
        sock.send("<br><h5><b>IP INFORMATION</b></h5><br>")
        sock.send("<b>IP</b>: %s<br>" % host['ip_str'])
        sock.send("<b>Organization</b>: %s<br>" % host.get('org', 'n/a'))
        sock.send("<b>Operating System</b>: %s<br>" % host.get('os', 'n/a'))

        # Print vuln information
        sock.send("<br><h5><b>VULN</b></h5><br>")
        for item in host['vulns']:
            CVE = item.replace('!','')
            sock.send('<b>Vulns</b>: %s<br>' % item)
            exploits = api.exploits.search(CVE)
            for item in exploits['matches']:
                if item.get('cve')[0] == CVE:
                    sock.send("<br><b>Desciption:</b><br>"+item.get('description')+"<br>")
    except: 'An error occured'
    sock.close()
    app.logger.info("Connection closed.")


@app.route('/')
def main():
    return render_template('index.html')

@app.route('/signUp')
def registration():
    return render_template('signUp.html')

@app.route('/signIn')
def login():
    return render_template('signIn.html')

if __name__ == "__main__":
    app.run()
    