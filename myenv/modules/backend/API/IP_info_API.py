import requests
import os
import Data_handling

class IPINFO:
    def __init__(self, IPINFO_API_TOKEN=None):
        self.IPINFO_API_TOKEN = IPINFO_API_TOKEN
        self.load_IPINFO_API_Key()

    # ================= PATH =================
    @staticmethod
    def _api_key_path():
        base = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base, "API_DB", "IPINFO_API_TOKEN.txt")

    # ================= API KEY =================
    def save_IPINFO_API_Key(self, API):
        with open(self._api_key_path(), "w") as fp:
            fp.write(API)
        self.IPINFO_API_TOKEN = API

    def load_IPINFO_API_Key(self):
        try:
            with open(self._api_key_path(), "r") as fp:
                self.IPINFO_API_TOKEN = fp.readline().strip()
        except FileNotFoundError:
            print("IPINFO API token not found.")

    # ================= SINGLE =================
    def IP_privacy_detection(self, ip_address):
        if not self.IPINFO_API_TOKEN:
            return "API token not set"

        url = f"https://ipinfo.io/{ip_address}/privacy?token={self.IPINFO_API_TOKEN}"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            print(data)
            return data
        return "Server error"

    # ================= BULK =================
    def bulk_ip_privacy_check_from_csv(self, input_csv, output_csv):
        ip_list = Data_handling.csv_to_list(input_csv)
        results = []

        for ip in ip_list:
            response = self.IP_privacy_detection(ip)
            if isinstance(response, dict):
                results.append(
                    f"{ip}, vpn={response.get('vpn')}, tor={response.get('tor')}, "
                    f"hosting={response.get('hosting')}, proxy={response.get('proxy')}, "
                    f"relay={response.get('relay')}, service={response.get('service')}"
                )
            else:
                results.append(f"{ip}, error")

        Data_handling.list_to_csv(results, output_csv)
