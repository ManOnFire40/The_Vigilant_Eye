import requests
import json
import Data_handling

IPDB_API= None
class IPDB:
    def __init__(self, IPDB_API  = None):
        self.IPDB_API = IPDB_API
        self.load_IPDB_API_Key()  # Call the function inside the constructor
                


    def save_IPDB_API_Key(self, API):
        try:
            with open('../API_DB/IPDB_API_Key.txt', 'w') as fp:
                fp.write(API)
        except FileNotFoundError as e:
            print(f"Please check the DB path")
            print(f"Error: {e}")
            return (f"Error: {e}")      

    def load_IPDB_API_Key(self):
        try:
            with open('../API_DB/IPDB_API_Key.txt', 'r') as fp:
                line = fp.readline()
                while line != '':
                    self.IPDB_API = str(line)
                return self.IPDB_API    
        except FileNotFoundError as e:
            print(f"Please check the DB path")
            print(f"Error: {e}")
            return (f"Error: {e}")       
        


    ### AbuseIPDB API Integration
    def get_ip_info_ipdb(self, ip_address):
        try:
            # Defining the api-endpoint
            url = 'https://api.abuseipdb.com/api/v2/check'
            querystring = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90'
            }
            headers = {
                'Accept': 'application/json',
                'Key': self.IPDB_API
            }
            response = requests.request(method='GET', url=url, headers=headers, params=querystring)
            # Formatted output
            decodedResponse = json.loads(response.text)
            print (json.dumps(decodedResponse, sort_keys=True, indent=4))
            return decodedResponse
        except Exception as e:
            error_message = str(f"Exception Error: {e}")
            print(error_message)
            return error_message



    def get_subnet_info_ipdb(self, subnet):
        try:
            # Defining the api-endpoint
            url = 'https://api.abuseipdb.com/api/v2/check-block'
            querystring = {
                'network':subnet,
                'maxAgeInDays':'15',
            }
            headers = {
                'Accept': 'application/json',
                'Key': self.IPDB_API
            }
            response = requests.request(method='GET', url=url, headers=headers, params=querystring)
            # Formatted output
            decodedResponse = json.loads(response.text)
            print (json.dumps(decodedResponse, sort_keys=True, indent=4))
            return decodedResponse
        except Exception as e:
            error_message = str(f"Exception Error: {e}")
            print(error_message)
            return error_message



def bulk_ip_check_ipdb_from_csv(self, input_csv, output_csv):
    ip_list = Data_handling.csv_to_list(input_csv)
    results = []

    for ip in ip_list:
        print(f"Checking IP (AbuseIPDB): {ip}")
        response = self.get_ip_info_ipdb(ip)

        if isinstance(response, dict):
            data = response.get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode", "N/A")
            isp = data.get("isp", "N/A")
            total_reports = data.get("totalReports", 0)

            results.append(
                f"{ip}, abuse_score={abuse_score}, country={country}, "
                f"isp={isp}, reports={total_reports}"
            )
        else:
            results.append(f"{ip}, error")

    Data_handling.list_to_csv(results, output_csv)



def bulk_subnet_check_ipdb_from_csv(self, input_csv, output_csv):
    subnet_list = Data_handling.csv_to_list(input_csv)
    results = []

    for subnet in subnet_list:
        print(f"Checking subnet (AbuseIPDB): {subnet}")
        response = self.get_subnet_info_ipdb(subnet)

        if isinstance(response, dict):
            data = response.get("data", {})
            total_ips = data.get("totalIps", 0)
            reported_ips = data.get("reportedIps", 0)
            abuse_score = data.get("abuseConfidenceScore", 0)

            results.append(
                f"{subnet}, total_ips={total_ips}, "
                f"reported_ips={reported_ips}, abuse_score={abuse_score}"
            )
        else:
            results.append(f"{subnet}, error")

    Data_handling.list_to_csv(results, output_csv)


