#https://help.shodan.io/guides/how-to-monitor-network   

#https://help.shodan.io/integrations/azure-sentinel

from shodan import Shodan
from shodan.helpers import get_ip
from shodan.cli.helpers import get_api_key


# Configuration
EMAIL_TO = 'davgui99@gmail.com'
EMAIL_FROM  = 'ics-alerts'

def send_mail(subject, content):
    """Send an email using a local mail server."""
    from smtplib import SMTP
    server = SMTP()
    server.connect()
    server.sendmail(EMAIL_FROM, EMAIL_TO, 'Subject: {}\n\n{}'.format(subject, content))
    server.quit()

# Setup the Shodan API connection
api = Shodan('W9YKu6EZhmfJEuzdu34weobtOf0WoSQC')

# Subscribe to results for all networks:
for banner in api.stream.alert():
    # Check whether the banner is from an ICS service
    if 'tags' in banner and 'ics' in banner['tags']:
        send_mail()


