from shodan import Shodan
from shodan.helpers import get_ip
from shodan.cli.helpers import get_api_key

# Setup the Shodan API connection
api = Shodan('tJiMTHh65vvJsgg4AaBtRRMZ844LFPpV')

print(api.delete_alert('R552AJ5B8M7LKWMB'))

print(api.alerts)
