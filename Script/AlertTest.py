from shodan import Shodan
from shodan.helpers import get_ip
from shodan.cli.helpers import get_api_key
import json

# Setup the Shodan API connection
api = Shodan('tJiMTHh65vvJsgg4AaBtRRMZ844LFPpV')

alertJson=api.create_alert("testAlert","167.114.198.227")


print(type(alertJson))
print(alertJson['id'])

print(api.alerts)
