import requests
import json
import os
import Data_handling

class IPDB:
    def __init__(self, IPDB_API=None):
        self.IPDB_API = IPDB_API
        self.load_IPDB_API_Key()

    # ================= PATH HANDLING =================
    @staticmethod
    def _api_key_path():
        base = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base, "API_DB", "IPDB_API_Key.txt")

    # ================= API KEY =================
    def save_IPDB_API_Key(self, API):
        try:
            with open(self._api_key_path(), "w") as fp:
                fp.write(API)
            self.IPDB_API = API
        except Exception as e:
            print(f"Error saving API key: {e}")

    def load_IPDB_API_Key(self):
        try:
            with open(self._api_key_path(), "r") as fp:
                self.IPDB_API = fp.readline().strip()
            return self.IPDB_API
        except FileNotFoundError:
            print("IPDB API key not found.")
            return None

    # ================= SINGLE LOOKUPS =================
    def get_ip_info_ipdb(self, ip_address):
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Accept": "application/json",
                "Key": self.IPDB_API
            }
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90
            }
            response = requests.get(url, headers=headers, params=params)
            data = response.json()
            print(json.dumps(data, indent=4))
            return data
        except Exception as e:
            return f"Exception Error: {e}"

    def get_subnet_info_ipdb(self, subnet):
        try:
            url = "https://api.abuseipdb.com/api/v2/check-block"
            headers = {
                "Accept": "application/json",
                "Key": self.IPDB_API
            }
            params = {
                "network": subnet,
                "maxAgeInDays": 15
            }
            response = requests.get(url, headers=headers, params=params)
            data = response.json()
            print(json.dumps(data, indent=4))
            return data
        except Exception as e:
            return f"Exception Error: {e}"

    # ================= BULK =================
    def bulk_ip_check_ipdb_from_csv(self, input_csv, output_csv):
        ip_list = Data_handling.csv_to_list(input_csv)
        results = []

        for ip in ip_list:
            response = self.get_ip_info_ipdb(ip)
            if isinstance(response, dict):
                d = response.get("data", {})
                results.append(
                    f"{ip}, abuse_score={d.get('abuseConfidenceScore',0)}, "
                    f"country={d.get('countryCode','N/A')}, "
                    f"isp={d.get('isp','N/A')}, reports={d.get('totalReports',0)}"
                )
            else:
                results.append(f"{ip}, error")

        Data_handling.list_to_csv(results, output_csv)

    def bulk_subnet_check_ipdb_from_csv(self, input_csv, output_csv):
        subnet_list = Data_handling.csv_to_list(input_csv)
        results = []

        for subnet in subnet_list:
            response = self.get_subnet_info_ipdb(subnet)
            if isinstance(response, dict):
                d = response.get("data", {})
                results.append(
                    f"{subnet}, total_ips={d.get('totalIps',0)}, "
                    f"reported_ips={d.get('reportedIps',0)}, "
                    f"abuse_score={d.get('abuseConfidenceScore',0)}"
                )
            else:
                results.append(f"{subnet}, error")

        Data_handling.list_to_csv(results, output_csv)
