import requests

IPINFO_API_TOKEN = None


def save_Virus_total_API_Key(API):
    try:
        with open('../API_DB/IPINFO_API_TOKEN.txt', 'w') as fp:
            fp.write(API)
    except FileNotFoundError as e:
        print(f"Please check the DB path")
        print(f"Error: {e}")
        return (f"Error: {e}")              




def load_IPINFO_API_Key():
    try:
        with open('../API_DB/IPINFO_API_TOKEN.txt', 'r') as fp:
            line = fp.readline()
            while line != '':
                IPINFO_API_TOKEN=str(line)
            return IPINFO_API_TOKEN    
    except FileNotFoundError as e:
        print(f"Please check the DB path")
        print(f"Error: {e}")
        return (f"Error: {e}")        





def IP_privacy_detection(ip_address):
    try:
        # Construct the API URL
        url = f'https://ipinfo.io/{ip_address}/privacy?token={IPINFO_API_TOKEN}'
        # Make the GET request to the API
        response = requests.get(url)
        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()
            print(f"IP Address: {ip_address}")
            print(f"VPN: {data.get('vpn')}")
            print(f"Tor: {data.get('tor')}")
            print(f"Hosting Provider: {data.get('hosting')}")
            print(f"Proxy: {data.get('proxy')}")
            print(f"Relay: {data.get('relay')}")
            print(f"Service: {data.get('service')}")
            return data
        else:
            print(f"Failed to retrieve data: {response.status_code}")
            return "Server error"
    except Exception as e:
        error_message = str(f"Exception Error: {e}")
        print(error_message)
        return error_message    
