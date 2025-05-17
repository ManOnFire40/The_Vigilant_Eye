import requests
import json


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



    def get_ips_info_ipdb(self, ip_addresses):
        try:
            # takes a list of ip addresses and returns a list of reports
            list_of_ip_addresses_reports = []
            for ip_address in ip_addresses:
                list_of_ip_addresses_reports.append(self.get_ip_info_ipdb(ip_address))
            return list_of_ip_addresses_reports
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

