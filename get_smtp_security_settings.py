import requests
import dns.resolver
import csv
import sys

# Function to retrieve DNS records for a given domain and record type
def get_records(domain, record_type):
    try:
        return str(dns.resolver.resolve(domain, record_type)[0])
    except (dns.resolver.NoAnswer, IndexError):  # No answer found or index error during resolution
        return 'Not found'
    except dns.resolver.NXDOMAIN:  # Domain does not exist
        return 'Not found'

# Function to retrieve MTA-STS TXT file content for a given domain
def get_mta_sts_txt(domain):
    try:
        url = f"https://{domain}/.well-known/mta-sts.txt"  # Construct the URL for MTA-STS TXT record
        response = requests.get(url)  # Send a GET request to the URL
        if response.status_code == 200:  # If response status code is 200 (OK)
            return str(response.text).strip()  # Return the content of the file, stripped of leading and trailing whitespace
        else:  # If response status code is not 200 (e.g., 404 Not Found)
            return "Not found"
    except (requests.RequestException, dns.resolver.NXDOMAIN):  # Request exception or domain does not exist
        return "Not found"

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
    except (dns.resolver.NoAnswer, IndexError):  # No answer found or index error during resolution
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
            return 'Not Found'
            pass  # No TLSA record found for this port
        except dns.resolver.NXDOMAIN:
            return 'Not found'
            pass  # Domain does not exist

        return tlsa_records 
 
# Main function to retrieve and write SMTP security settings for a list of domains to a CSV file
def get_smtp_records(domains, output_file, local_nameserver):
    with open(output_file, 'w', newline='') as csvfile:  # Open the output CSV file in write mode
        fieldnames = ['domain', 'dnssec', 'mx', 'caA', 'spf', 'dmarc', 'mta-sts', 'ipv4-mta-sts', 'ipv6-mta-sts', 'mta-report', 'tlsa', 'mta_sts_txt']  # Define the CSV field names
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)  # Create a CSV writer object with the defined field names
        writer.writeheader()  # Write header row to the CSV file

        for domain in domains:  # Iterate through the list of domains
            try:
                dnssec = IsDNSSEC_signed(domain, local_nameserver)  # Check if the given domain is DNSSEC signed by the specified nameserver
                mx_records = dns.resolver.resolve(domain, 'MX')  # Retrieve MX records for the given domain
                caA = get_records(domain, 'CAA')  # Retrieve CA/A record for the given domain
                spf = 'Not found'  # Initialize spf variable with default value
                spf_records = dns.resolver.resolve(domain, 'TXT')  # Retrieve TXT records for the given domain

                for record in spf_records:  # Iterate through the list of TXT records
                    if str(record).lower().startswith('"v=spf'):  # Check if the first character sequence is "v=spf" (case-insensitive)
                        spf = str(record)  # Update spf variable with the retrieved SPF record
                        break  # Exit the loop once a matching SPF record is found

                dmarc = get_records('_dmarc.' + domain, 'TXT')  # Retrieve DMARC record for the given domain
  
                if dnssec == True: # No reason to look for RRs that require zone to be signed
                    tlsa = get_tlsa_records(domain, local_nameserver)  # Retrieve TLSA records for the given domain
                    mta_sts = get_records('_mta-sts.' + domain, 'TXT')  # Retrieve MTA-STS record for the given domain
                    ipv4_mta_sts = get_records('mta-sts.' + domain, 'A')  # Retrieve IPv4 MTA-STS record for the given domain
                    ipv6_mta_sts = get_records('mta-sts.' + domain, 'AAAA')  # Retrieve IPv6 MTA-STS record for the given domain
                    mta_report = get_records('_smtp._tls.' + domain, 'TXT')  # Retrieve SMTP report record for the given domain

                    if mta_sts:  # If an MTA-STS record is found
                        mta_sts_txt = get_mta_sts_txt(domain)  # Retrieve MTA-STS TXT file content for the given domain
                    else:  # If no MTA-STS record is found
                        mta_sts_txt = 'Not found'
                else:
                    tlsa = 'Not found'

                for record in mx_records:  # Iterate through the list of MX records
                    writer.writerow({'domain': domain, 'dnssec': dnssec, 'mx': str(record), 'caA': caA, 'spf': spf, 'dmarc': dmarc, 'mta-sts': mta_sts, 'ipv4-mta-sts': ipv4_mta_sts, 'ipv6-mta-sts': ipv6_mta_sts, 'mta-report': mta_report, 'tlsa': get_tlsa_records(domain, local_nameserver), 'mta_sts_txt': mta_sts_txt})  # Write a row to the CSV file with SMTP security settings
            except dns.resolver.NoAnswer:  # No answer found during resolution
                writer.writerow({'domain': domain, 'dnssec': 'No', 'mx': 'No MX records found', 'caA': get_records(domain, 'CAA'), 'spf': 'Not found', 'dmarc': 'Not found', 'mta-sts': 'Not found', 'ipv4-mta-sts': 'Not found', 'ipv6-mta-sts': 'Not found', 'mta-report': 'Not found', 'tlsa': get_tlsa_records(domain, local_nameserver), 'mta_sts_txt': 'Not found'})  # Write a row to the CSV file with default values for SMTP security settings
            except dns.resolver.NXDOMAIN:  # Domain does not exist
                writer.writerow({'domain': domain, 'dnssec': 'No', 'mx': 'No MX records found', 'caA': get_records(domain, 'CAA'), 'spf': 'Not found', 'dmarc': 'Not found', 'mta-sts': 'Not found', 'ipv4-mta-sts': 'Not found', 'ipv6-mta-sts': 'Not found', 'mta-report': 'Not found', 'tlsa': get_tlsa_records(domain, local_nameserver), 'mta_sts_txt': 'Not found'})  # Write a row to the CSV file with default values for SMTP security settings

# Call the main function with command-line arguments
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print('Usage: python get_smtp_security_settings.py domains.txt mx_records.csv nameserver')
        sys.exit(1)

    domains = [line.strip() for line in open(sys.argv[1])]
    output_file = sys.argv[2]
    local_nameserver = [sys.argv[3]]

    get_smtp_records(domains, output_file, local_nameserver)
