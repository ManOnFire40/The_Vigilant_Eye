import requests
import json
import urllib.parse
class VirusTotal:
    def __init__(self, Virus_total_api_key=None):
        self.Virus_total_api_key = Virus_total_api_key
        self.load_Virus_total_API_Key()  # Call the function inside the constructor

    ##Virus_total_api_key need to be with a paid account

    @staticmethod
    def save_Virus_total_API_Key(API):
        try:
            with open('../API_DB/VirusTotal_API_Key.txt', 'w') as fp:
                fp.write(API)
        except FileNotFoundError as e:
            print(f"Please check the DB path")
            print(f"Error: {e}")
            return (f"Error: {e}")              

    @staticmethod
    def load_Virus_total_API_Key():
        try:
            with open('../API_DB/VirusTotal_API_Key.txt', 'r') as fp:
                line = fp.readline()
                return line.strip()
        except FileNotFoundError as e:
            print(f"Please check the DB path")
            print(f"Error: {e}")
            return (f"Error: {e}")
        





    ######################VirusTotal API Integration
    #### Virus file reports

    # Get a file report
    def get_file_reports_with_hash_virustotal(self, file_hash):
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {
                "accept": "application/json",
                "x-apikey": self.Virus_total_api_key
            }
            response = requests.get(url, headers=headers)
            decodedResponse = json.loads(response.text)
            print(response.text)
            return decodedResponse
        except Exception as e:
            error_message = str(f"Exception Error: {e}")
            print(error_message)
            return error_message

    # Get file behaviour summary
    def get_file_summary_virustotal(self, file_hash):
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary"
            headers = {
                "accept": "application/json",
                "x-apikey": self.Virus_total_api_key
            }
            response = requests.get(url, headers=headers)
            decodedResponse = json.loads(response.text)
            print(response.text)
            return decodedResponse
        except Exception as e:
            error_message = str(f"Exception Error: {e}")
            print(error_message)
            return error_message

    # Get the behavior trees for a file
    def get_file_behaviour_mitre_trees_virustotal(self, file_hash):
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_mitre_trees"
            headers = {
                "accept": "application/json",
                "x-apikey": self.Virus_total_api_key
            }
            response = requests.get(url, headers=headers)
            decodedResponse = json.loads(response.text)
            print(response.text)
            return decodedResponse
        except Exception as e:
            error_message = str(f"Exception Error: {e}")
            print(error_message)
            return error_message

    # Get all behavior reports for a file
    def get_file_behaviour_reports_virustotal(self, file_hash):
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviours"
            headers = {
                "accept": "application/json",
                "x-apikey": self.Virus_total_api_key
            }
            response = requests.get(url, headers=headers)
            decodedResponse = json.loads(response.text)
            print(response.text)
            return decodedResponse
        except Exception as e:
            error_message = str(f"Exception Error: {e}")
            print(error_message)
            return error_message

    # Scan a URL
    def scan_URL(self, URL):
        try:
            url = "https://www.virustotal.com/api/v3/urls"
            payload = { "url": URL }
            headers = {
                "accept": "application/json",
                "x-apikey": self.Virus_total_api_key,
                "content-type": "application/x-www-form-urlencoded"
            }
            response = requests.post(url, data=payload, headers=headers)
            print(response.text)
            decodedResponse = json.loads(response.text)
            return decodedResponse
        except Exception as e:
            error_message = str(f"Exception Error: {e}")
            print(error_message)
            return error_message

    # Get URL report
    def get_url_report(self, URL):
        try: 
            Encoded_url = urllib.parse.quote(URL, safe='')
            url = f"https://www.virustotal.com/api/v3/urls/{Encoded_url}"
            headers = {
                "accept": "application/json",
                "x-apikey": self.Virus_total_api_key
            }
            response = requests.get(url, headers=headers)
            print(response.text)
            decodedResponse = json.loads(response.text)
            return decodedResponse
        except Exception as e:
            error_message = str(f"Exception Error: {e}")
            print(error_message)
            return error_message

    # Get a domain report
    def get_domain_report(self, domain):
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {
                "accept": "application/json",
                "x-apikey": self.Virus_total_api_key
            }
            response = requests.get(url, headers=headers)
            print(response.text)
            decodedResponse = json.loads(response.text)
            return decodedResponse
        except Exception as e:
            error_message = str(f"Exception Error: {e}")
            print(error_message)
            return error_message

    # Get DNS resolution object for a domain
    def get_dns_resolution(self, domain):
        try:
            url = f"https://www.virustotal.com/api/v3/resolutions/{domain}"
            headers = {
                "accept": "application/json",
                "x-apikey": self.Virus_total_api_key
            }
            response = requests.get(url, headers=headers)
            print(response.text)
            decodedResponse = json.loads(response.text)
            return decodedResponse
        except Exception as e:
            error_message = str(f"Exception Error: {e}")
            print(error_message)
            return error_message
