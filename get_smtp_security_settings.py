import requests
import dns.resolver
import csv
import sys

# Function to retrieve DNS records for a given domain and record type
def get_records(domain, record_type):
    try:
        return str(dns.resolver.resolve(domain, record_type)[0])
    except (dns.resolver.NoAnswer, IndexError):  # No answer found or index error during resolution
        return 'False'
    except dns.resolver.NXDOMAIN:  # Domain does not exist
        return 'False'

# Function to retrieve MTA-STS TXT file content for a given domain
def get_mta_sts_txt(domain):
    try:
        url = f"https://{domain}/.well-known/mta-sts.txt"  # Construct the URL for MTA-STS TXT record
        response = requests.get(url, timeout=5)  # Added timeout to prevent hanging
        if response.status_code == 200:  # If response status code is 200 (OK)
            return str(response.text).strip()  # Return the content of the file
        else:  # If response status code is not 200
            return "False"
    except (requests.RequestException, dns.resolver.NXDOMAIN):  # Request exception or domain does not exist
        return "False"

# Function to check if a given domain is DNSSEC signed by the specified nameserver
def IsDNSSEC_signed(domain, nameserver):
    resolver = dns.resolver.Resolver()  # Create a DNS resolver object
    resolver.nameservers = nameserver  # Set the DNS server to use for resolution
    try:
        dnskey = next((rr for rr in resolver.resolve(domain, 'DNSKEY') if rr.flags == 256 or rr.flags == 257), None)  # Find the DNSKEY record
        if dnskey:  # If a DNSKEY record is found
            return True  # Return True indicating that the domain is DNSSEC signed
        else:
            return False  # Return False indicating that the domain is not DNSSEC signed
    except (dns.resolver.NoAnswer, IndexError, dns.resolver.NXDOMAIN):  # Added NXDOMAIN to catch missing domains safely
        return False

# Function to retrieve TLSA records for a given domain and nameserver
def get_tlsa_records(domain, nameserver):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = nameserver

    tlsa_records = []
    for port in ['_25._tcp.', '_465._tcp.', '_587._tcp.', '_993._tcp.', '_995._tcp.']:
        try:
            tlsa_record = str(resolver.resolve(port + domain, 'TLSA')[0])
            tlsa_records.append(tlsa_record)
        except (dns.resolver.NoAnswer, IndexError):
            pass  # Removed the abrupt 'return' statement so it loops through all ports
        except dns.resolver.NXDOMAIN:
            pass

    return tlsa_records if tlsa_records else 'False'
 
# Main function to retrieve and write SMTP security settings for a list of domains to a CSV file
def get_smtp_records(domains, output_file, local_nameserver):
    with open(output_file, 'w', newline='') as csvfile:  # Open the output CSV file in write mode
        fieldnames = ['domain', 'dnssec', 'mx', 'caA', 'spf', 'dmarc', 'mta-sts', 'ipv4-mta-sts', 'ipv6-mta-sts', 'mta-report', 'tlsa', 'mta_sts_txt']  # Define the CSV field names
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)  # Create a CSV writer object with the defined field names
        writer.writeheader()  # Write header row to the CSV file

        for domain in domains:  # Iterate through the list of domains
            try:
                dnssec = IsDNSSEC_signed(domain, local_nameserver)  # Check if the given domain is DNSSEC signed
                mx_records = dns.resolver.resolve(domain, 'MX')  # Retrieve MX records for the given domain
                caA = get_records(domain, 'CAA')  # Retrieve CA/A record for the given domain
                spf = 'False'  # Initialize spf variable with default value
                spf_records = dns.resolver.resolve(domain, 'TXT')  # Retrieve TXT records for the given domain

                for record in spf_records:  # Iterate through the list of TXT records
                    if str(record).lower().startswith('"v=spf'):  # Check if sequence is "v=spf"
                        spf = str(record)  # Update spf variable with the retrieved SPF record
                        break  # Exit the loop once a matching SPF record is found

                dmarc = get_records('_dmarc.' + domain, 'TXT')  # Retrieve DMARC record for the given domain
  
                # --- FIX: Define Fallback Defaults Before Using Conditional Logic ---
                tlsa = 'False'
                mta_sts = 'False'
                ipv4_mta_sts = 'False'
                ipv6_mta_sts = 'False'
                mta_report = 'False'
                mta_sts_txt = 'False'

                if dnssec: # Looks up RRs if the zone is signed
                    tlsa = get_tlsa_records(domain, local_nameserver)  
                    mta_sts = get_records('_mta-sts.' + domain, 'TXT')  
                    ipv4_mta_sts = get_records('mta-sts.' + domain, 'A')  
                    ipv6_mta_sts = get_records('mta-sts.' + domain, 'AAAA')  
                    mta_report = get_records('_smtp._tls.' + domain, 'TXT')  

                    if mta_sts and mta_sts != 'False':  
                        mta_sts_txt = get_mta_sts_txt(domain)  

                for record in mx_records:  # Iterate through the list of MX records
                    writer.writerow({
                        'domain': domain, 'dnssec': dnssec, 'mx': str(record), 'caA': caA, 'spf': spf, 
                        'dmarc': dmarc, 'mta-sts': mta_sts, 'ipv4-mta-sts': ipv4_mta_sts, 
                        'ipv6-mta-sts': ipv6_mta_sts, 'mta-report': mta_report, 'tlsa': tlsa, 
                        'mta_sts_txt': mta_sts_txt
                    })
            except dns.resolver.NoAnswer:  # No answer found during resolution
                writer.writerow({'domain': domain, 'dnssec': 'No', 'mx': 'No MX records found', 'caA': get_records(domain, 'CAA'), 'spf': 'False', 'dmarc': 'False', 'mta-sts': 'False', 'ipv4-mta-sts': 'False', 'ipv6-mta-sts': 'False', 'mta-report': 'False', 'tlsa': 'False', 'mta_sts_txt': 'False'})
            except dns.resolver.NXDOMAIN:  # Domain does not exist
                writer.writerow({'domain': domain, 'dnssec': 'No', 'mx': 'No MX records found', 'caA': get_records(domain, 'CAA'), 'spf': 'False', 'dmarc': 'False', 'mta-sts': 'False', 'ipv4-mta-sts': 'False', 'ipv6-mta-sts': 'False', 'mta-report': 'False', 'tlsa': 'False', 'mta_sts_txt': 'False'})

# Call the main function with command-line arguments
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print('Usage: python get_smtp_security_settings.py domains.txt mx_records.csv nameserver')
        sys.exit(1)

    domains = [line.strip() for line in open(sys.argv[1])]
    output_file = sys.argv[2]
    local_nameserver = [sys.argv[3]]

    get_smtp_records(domains, output_file, local_nameserver)