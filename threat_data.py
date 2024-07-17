import requests
from OTXv2 import OTXv2
import pandas as pd

OTX_API_KEY = 'Your_OTX_API_Key'
PULSE_ID = 'pulse_id'  # replace with your pulse id

def get_threat_data():
    # Send a request to the Cyber Cure API
    response = requests.get('https://api.cybercure.ai/feed/get_ips')

    # Parse the JSON response
    data = response.json()

    # Get the list of IP addresses
    ip_addresses = data['data']['ip']

    return ip_addresses

def get_pulse_data():
    # Initialize the OTX API
    otx = OTXv2(OTX_API_KEY)

    # Get the pulse (threat) by id
    pulse = otx.get_pulse_details(PULSE_ID)

    return pulse

def process_threat_data(pulse):
    # Create a DataFrame from the pulse
    df = pd.DataFrame(pulse['indicators'])

    # Count the number of each type of threat
    threat_counts = df['type'].value_counts()

    # Calculate the percentage of each type of threat
    threat_percentages = (threat_counts / threat_counts.sum()) * 100

    return threat_percentages.to_dict()

