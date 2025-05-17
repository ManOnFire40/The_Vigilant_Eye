import requests
class IPINFO:
    def __init__(self, IPINFO_API_TOKEN=None):
        self.IPINFO_API_TOKEN = IPINFO_API_TOKEN
        self.load_IPINFO_API_Key()  # Call the function inside the constructor

    ##IPINFO_API_TOKEN need to be with a paid account

    def save_IPINFO_API_Key(self, API):
        try:
            with open('../API_DB/IPINFO_API_TOKEN.txt', 'w') as fp:
                fp.write(API)
            self.IPINFO_API_TOKEN = API
        except FileNotFoundError as e:
            print(f"Please check the DB path")
            print(f"Error: {e}")
            return (f"Error: {e}")              

    def load_IPINFO_API_Key(self):
        try:
            with open('../API_DB/IPINFO_API_TOKEN.txt', 'r') as fp:
                line = fp.readline().strip()
                self.IPINFO_API_TOKEN = line
                return self.IPINFO_API_TOKEN
        except FileNotFoundError as e:
            print(f"Please check the DB path")
            print(f"Error: {e}")
            return (f"Error: {e}")        

    def IP_privacy_detection(self, ip_address):
        try:
            if not self.IPINFO_API_TOKEN:
                print("API token is not set.")
                return "API token is not set."
            # Construct the API URL
            url = f'https://ipinfo.io/{ip_address}/privacy?token={self.IPINFO_API_TOKEN}'
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
