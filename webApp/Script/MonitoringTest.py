#https://help.shodan.io/guides/how-to-monitor-network   

#https://help.shodan.io/integrations/azure-sentinel

from shodan import Shodan
from shodan.helpers import get_ip
from shodan.cli.helpers import get_api_key
import sys


# Configuration
EMAIL_TO = 'davgui99@gmail.com'
EMAIL_FROM  = 'vuln-alerts'

if len(sys.argv)==2:
    EMAIL_TO = sys.argv[1]

print("Email to: "+EMAIL_TO+" from: "+EMAIL_FROM)

#def send_mail(subject, content):
def send_mail():
    """Send an email using a local mail server."""
    from smtplib import SMTP
    server = SMTP()
    server.connect()
    #server.sendmail(EMAIL_FROM, EMAIL_TO, 'Subject: {}\n\n{}'.format(subject, content))
    server.sendmail(EMAIL_FROM, EMAIL_TO, 'Rilevata nuova vulnerabilità')
    server.quit()

# Setup the Shodan API connection
api = Shodan('tJiMTHh65vvJsgg4AaBtRRMZ844LFPpV')


# Subscribe to results for all networks:
for banner in api.stream.alert(): 
    print("arrivato alert")
    #print(banner)
    send_mail()
    # Check whether the banner is from an ICS service
    #if 'tags' in banner and 'vulns' in banner['tags']:
    #    send_mail()

