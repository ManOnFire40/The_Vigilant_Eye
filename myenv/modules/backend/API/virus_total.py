import requests
import json
import urllib.parse
import os
import Data_handling


class VirusTotal:
    def __init__(self, Virus_total_api_key=None):
        self.Virus_total_api_key = Virus_total_api_key or self.load_Virus_total_API_Key()

    # =========================
    # PATH HANDLING
    # =========================
    @staticmethod
    def _api_key_path():
        base_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base_dir, "API_DB", "VirusTotal_API_Key.txt")

    # =========================
    # API KEY MANAGEMENT
    # =========================
    @staticmethod
    def save_Virus_total_API_Key(API):
        try:
            with open(VirusTotal._api_key_path(), "w") as fp:
                fp.write(API)
        except Exception as e:
            print(f"Error saving API key: {e}")

    @staticmethod
    def load_Virus_total_API_Key():
        try:
            with open(VirusTotal._api_key_path(), "r") as fp:
                return fp.readline().strip()
        except FileNotFoundError:
            print("VirusTotal API key not found.")
            return None

    def _headers(self):
        if not self.Virus_total_api_key:
            raise ValueError("VirusTotal API key not set")
        return {
            "accept": "application/json",
            "x-apikey": self.Virus_total_api_key
        }

    # =========================
    # FILE ANALYSIS
    # =========================
    def get_file_reports_with_hash_virustotal(self, file_hash):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(url, headers=self._headers())
        print(response.text)
        return response.json()

    def get_file_summary_virustotal(self, file_hash):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary"
        response = requests.get(url, headers=self._headers())
        print(response.text)
        return response.json()

    def get_file_behaviour_mitre_trees_virustotal(self, file_hash):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_mitre_trees"
        response = requests.get(url, headers=self._headers())
        print(response.text)
        return response.json()

    def get_file_behaviour_reports_virustotal(self, file_hash):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviours"
        response = requests.get(url, headers=self._headers())
        print(response.text)
        return response.json()

    # =========================
    # URL ANALYSIS
    # =========================
    def scan_URL(self, URL):
        url = "https://www.virustotal.com/api/v3/urls"
        headers = self._headers()
        headers["content-type"] = "application/x-www-form-urlencoded"
        payload = {"url": URL}

        response = requests.post(url, data=payload, headers=headers)
        print(response.text)
        return response.json()

    def get_url_report(self, URL):
        encoded_url = urllib.parse.quote(URL, safe="")
        url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        response = requests.get(url, headers=self._headers())
        print(response.text)
        return response.json()

    # =========================
    # DOMAIN ANALYSIS
    # =========================
    def get_domain_report(self, domain):
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=self._headers())
        print(response.text)
        return response.json()

    def get_dns_resolution(self, domain):
        url = f"https://www.virustotal.com/api/v3/resolutions/{domain}"
        response = requests.get(url, headers=self._headers())
        print(response.text)
        return response.json()

    # =========================
    # BULK OPERATIONS
    # =========================
    def bulk_file_hash_check_from_csv(self, input_csv, output_csv):
        hashes = Data_handling.csv_to_list(input_csv)
        results = []

        for file_hash in hashes:
            print(f"Checking hash: {file_hash}")
            response = self.get_file_reports_with_hash_virustotal(file_hash)

            if isinstance(response, dict):
                stats = response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                results.append(
                    f"{file_hash}, malicious={stats.get('malicious', 0)}, "
                    f"suspicious={stats.get('suspicious', 0)}, "
                    f"harmless={stats.get('harmless', 0)}"
                )
            else:
                results.append(f"{file_hash}, error")

        Data_handling.list_to_csv(results, output_csv)

    def bulk_domain_check_from_csv(self, input_csv, output_csv):
        domains = Data_handling.csv_to_list(input_csv)
        results = []

        for domain in domains:
            print(f"Checking domain: {domain}")
            response = self.get_domain_report(domain)

            if isinstance(response, dict):
                stats = response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                results.append(
                    f"{domain}, malicious={stats.get('malicious', 0)}, "
                    f"suspicious={stats.get('suspicious', 0)}, "
                    f"harmless={stats.get('harmless', 0)}"
                )
            else:
                results.append(f"{domain}, error")

        Data_handling.list_to_csv(results, output_csv)

    def bulk_url_check_from_csv(self, input_csv, output_csv):
        urls = Data_handling.csv_to_list(input_csv)
        results = []

        for url in urls:
            print(f"Checking URL: {url}")
            response = self.get_url_report(url)

            if isinstance(response, dict):
                stats = response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                results.append(
                    f"{url}, malicious={stats.get('malicious', 0)}, "
                    f"suspicious={stats.get('suspicious', 0)}, "
                    f"harmless={stats.get('harmless', 0)}"
                )
            else:
                results.append(f"{url}, error")

        Data_handling.list_to_csv(results, output_csv)
