from backend.API.Abuse_IPDB import IPDB
from backend.API.IP_info_API import IPINFO
from backend.API.virus_total import VirusTotal

def print_main_menu():
    print("\n===== THE VIGILANT EYE =====")
    print("1. AbuseIPDB")
    print("2. IPINFO")
    print("3. VirusTotal")
    print("0. Exit")

def print_abuseipdb_menu():
    print("\n--- AbuseIPDB ---")
    print("1. Check single IP")
    print("2. Check subnet")
    print("3. Bulk IP check from CSV")
    print("4. Bulk subnet check from CSV")
    print("0. Back")

def print_ipinfo_menu():
    print("\n--- IPINFO ---")
    print("1. IP Privacy Detection")
    print("2. Bulk IP Privacy Check from CSV")
    print("0. Back")

def print_virustotal_menu():
    print("\n--- VirusTotal ---")
    print("1. File report by hash")
    print("2. File behaviour summary")
    print("3. File MITRE trees")
    print("4. File behaviour reports")
    print("5. Scan URL")
    print("6. URL report")
    print("7. Domain report")
    print("8. DNS resolution")
    print("9. Bulk hash check from CSV")
    print("10. Bulk domain check from CSV")
    print("11. Bulk URL check from CSV")
    print("0. Back")

def main():
    ipdb = IPDB()
    ipinfo = IPINFO()
    vt = VirusTotal(VirusTotal.load_Virus_total_API_Key())

    while True:
        print_main_menu()
        choice = input("Select an option: ")

        # ===================== AbuseIPDB =====================
        if choice == "1":
            while True:
                print_abuseipdb_menu()
                sub = input("Select option: ")

                if sub == "1":
                    ip = input("Enter IP address: ")
                    ipdb.get_ip_info_ipdb(ip)

                elif sub == "2":
                    subnet = input("Enter subnet (e.g. 1.1.1.0/24): ")
                    ipdb.get_subnet_info_ipdb(subnet)

                elif sub == "3":
                    in_csv = input("Input CSV path: ")
                    out_csv = input("Output CSV path: ")
                    ipdb.bulk_ip_check_ipdb_from_csv(in_csv, out_csv)

                elif sub == "4":
                    in_csv = input("Input CSV path: ")
                    out_csv = input("Output CSV path: ")
                    ipdb.bulk_subnet_check_ipdb_from_csv(in_csv, out_csv)

                elif sub == "0":
                    break

        # ===================== IPINFO =====================
        elif choice == "2":
            while True:
                print_ipinfo_menu()
                sub = input("Select option: ")

                if sub == "1":
                    ip = input("Enter IP address: ")
                    ipinfo.IP_privacy_detection(ip)

                elif sub == "2":
                    in_csv = input("Input CSV path: ")
                    out_csv = input("Output CSV path: ")
                    ipinfo.bulk_ip_privacy_check_from_csv(in_csv, out_csv)

                elif sub == "0":
                    break

        # ===================== VirusTotal =====================
        elif choice == "3":
            while True:
                print_virustotal_menu()
                sub = input("Select option: ")

                if sub == "1":
                    h = input("Enter file hash: ")
                    vt.get_file_reports_with_hash_virustotal(h)

                elif sub == "2":
                    h = input("Enter file hash: ")
                    vt.get_file_summary_virustotal(h)

                elif sub == "3":
                    h = input("Enter file hash: ")
                    vt.get_file_behaviour_mitre_trees_virustotal(h)

                elif sub == "4":
                    h = input("Enter file hash: ")
                    vt.get_file_behaviour_reports_virustotal(h)

                elif sub == "5":
                    url = input("Enter URL: ")
                    vt.scan_URL(url)

                elif sub == "6":
                    url = input("Enter URL: ")
                    vt.get_url_report(url)

                elif sub == "7":
                    domain = input("Enter domain: ")
                    vt.get_domain_report(domain)

                elif sub == "8":
                    domain = input("Enter domain: ")
                    vt.get_dns_resolution(domain)

                elif sub == "9":
                    in_csv = input("Input CSV path: ")
                    out_csv = input("Output CSV path: ")
                    vt.bulk_file_hash_check_from_csv(in_csv, out_csv)

                elif sub == "10":
                    in_csv = input("Input CSV path: ")
                    out_csv = input("Output CSV path: ")
                    vt.bulk_domain_check_from_csv(in_csv, out_csv)

                elif sub == "11":
                    in_csv = input("Input CSV path: ")
                    out_csv = input("Output CSV path: ")
                    vt.bulk_url_check_from_csv(in_csv, out_csv)

                elif sub == "0":
                    break

        elif choice == "0":
            print("Exiting...")
            break

        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
