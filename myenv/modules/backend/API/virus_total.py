import requests
import json
import urllib.parse

Virus_total_api_key = None


def save_Virus_total_API_Key(API):
    try:
        with open('../API_DB/VirusTotal_API_Key.txt', 'w') as fp:
            fp.write(API)
    except FileNotFoundError as e:
        print(f"Please check the DB path")
        print(f"Error: {e}")
        return (f"Error: {e}")              



def load_Virus_total_API_Key():
    try:
        with open('../API_DB/VirusTotal_API_Key.txt', 'r') as fp:
            line = fp.readline()
            while line != '':
                Virus_total_api_key=str(line)
            return Virus_total_api_key    
    except FileNotFoundError as e:
        print(f"Please check the DB path")
        print(f"Error: {e}")
        return (f"Error: {e}")
    





######################VirusTotal API Integration
#### Virus file reports
# Get a file report
def get_file_reports_with_hash_virustotal(file_hash):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "accept": "application/json",
            "x-apikey": Virus_total_api_key
        }
        response = requests.get(url, headers=headers)
        decodedResponse = json.loads(response.text)
        print(response.text)
        return decodedResponse
    except Exception as e:
        error_message = str(f"Exception Error: {e}")
        print(error_message)
        return error_message


# Get a summary of all behavior reports for a file
def get_file_summary_virustotal(file_hash):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary"
        headers = {
            "accept": "application/json",
            "x-apikey": Virus_total_api_key
        }
        response = requests.get(url, headers=headers)
        decodedResponse = json.loads(response.text)
        print(response.text)
        return decodedResponse
    except Exception as e:
        error_message = str(f"Exception Error: {e}")
        print(error_message)
        return error_message



def get_file_behaviour_mitre_trees_virustotal(file_hash):
    try:
        # Get the behavior trees for a file
        # The behavior trees are a set of nodes that represent the behavior of the file
        # The nodes are connected by edges that represent the relationships between the nodes
        # The behavior trees are used to identify the behavior of the file and to classify it
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_mitre_trees"

        headers = {
            "accept": "application/json",
            "x-apikey": Virus_total_api_key
        }

        response = requests.get(url, headers=headers)
        decodedResponse = json.loads(response.text)
        print(response.text)
        return decodedResponse
    except Exception as e:
        error_message = str(f"Exception Error: {e}")
        print(error_message)
        return error_message



def get_file_behaviour_reports_virustotal(file_hash):
    try:
        # Get all behavior reports for a file
        # This endpoint returns behavioural information from each sandbox about the file.
        # This API call returns all fields contained in the File behaviour object.
        # Note some of the entries have been truncated for readability.
        # The behaviour object contains the following fields:
        # - behaviour: The behaviour of the file
        # - behaviour_summary: A summary of the behaviour of the file
        # - behaviour_mitre_trees: The behavior trees for the file
        # - behaviour_reports: The behavior reports for the file
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviours"
        headers = {
            "accept": "application/json",
            "x-apikey": Virus_total_api_key
        }
        response = requests.get(url, headers=headers)
        decodedResponse = json.loads(response.text)
        print(response.text)
        return decodedResponse
    except Exception as e:
        error_message = str(f"Exception Error: {e}")
        print(error_message)
        return error_message


#### Virus URL reports
def scan_URL(URL, Virus_total_api_key):
    try:
        url = "https://www.virustotal.com/api/v3/urls"
        payload = { "url": URL }
        headers = {
            "accept": "application/json",
            "x-apikey": Virus_total_api_key,
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


# Get a URL report

def get_url_report(URL):
    try: 
        Encoded_url= urllib.parse.quote(URL, safe='')
        url = f"https://www.virustotal.com/api/v3/urls/{Encoded_url}"
        headers = {
            "accept": "application/json",
            "x-apikey": Virus_total_api_key
        }
        response = requests.get(url, headers=headers)
        print(response.text)
        decodedResponse = json.loads(response.text)
        return decodedResponse
    except Exception as e:
        error_message = str(f"Exception Error: {e}")
        print(error_message)
        return error_message


#### Virus domain reports
def get_domain_report(domain):
    try:
        # Get a domain report
        # This endpoint returns the domain report for the given domain.
        # The domain report contains the following fields:
        # - domain: The domain name
        # - last_analysis_stats: The last analysis stats for the domain
        # - last_analysis_results: The last analysis results for the domain
        # - last_analysis_date: The last analysis date for the domain
        # - creation_date: The creation date for the domain
        # - expiration_date: The expiration date for the domain
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"

        headers = {
            "accept": "application/json",
            "x-apikey": Virus_total_api_key
        }
        response = requests.get(url, headers=headers)
        print(response.text)
        decodedResponse = json.loads(response.text)
        return decodedResponse
    except Exception as e:
        error_message = str(f"Exception Error: {e}")
        print(error_message)
        return error_message


# Get a DNS resolution object
def get_dns_resolution(domain):
    # Get a DNS resolution object
    # This endpoint returns the DNS resolution object for the given domain.
    # The DNS resolution object contains the following fields:
    # - domain: The domain name
    # - last_analysis_stats: The last analysis stats for the domain
    # - last_analysis_results: The last analysis results for the domain
    # - last_analysis_date: The last analysis date for the domain
    # - creation_date: The creation date for the domain
    # - expiration_date: The expiration date for the domain
    try:
        url = f"https://www.virustotal.com/api/v3/resolutions/{domain}"
        headers = {
            "accept": "application/json",
            "x-apikey": Virus_total_api_key
        }
        response = requests.get(url, headers=headers)
        print(response.text)
        decodedResponse = json.loads(response.text)
        return decodedResponse
    except Exception as e:
        error_message = str(f"Exception Error: {e}")
        print(error_message)
        return error_message


