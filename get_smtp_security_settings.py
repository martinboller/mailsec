import requests
import dns.resolver
import csv
import sys

def get_records(domain, record_type):
    try:
        return str(dns.resolver.resolve(domain, record_type)[0])
    except (dns.resolver.NoAnswer, IndexError):
        return 'Not found'
    except dns.resolver.NXDOMAIN:
        return 'Not found'

def get_mta_sts_txt(domain):
    try:
        url = f"https://{domain}/.well-known/mta-sts.txt"
        response = requests.get(url)
        if response.status_code == 200:
            return str(response.text).strip()
        else:
            return "Not found"
    except (requests.RequestException, dns.resolver.NXDOMAIN):
        return "Not found"
        pass

def IsDNSSEC_signed(domain, nameserver):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = nameserver

    try:
        dnskey = next((rr for rr in resolver.resolve(domain, 'DNSKEY') if rr.flags == 256 or rr.flags == 257), None)  # Check if DNSKEY flags are set to 256 (DNSSEC signing key)
        if dnskey:
            return True
        else:
            return False
    except (dns.resolver.NoAnswer, IndexError):
        return False

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

def get_mx_records(domains, output_file, local_nameserver):
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['domain', 'dnssec', 'mx', 'caA', 'spf', 'dmarc', 'mta-sts', 'ipv4-mta-sts', 'ipv6-mta-sts', 'mta-report', 'tlsa', 'mta_sts_txt']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for domain in domains:
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                caA = get_records(domain, 'CAA')
            
                spf = 'Not found'  # Initialize spf variable with default value
                spf_records = dns.resolver.resolve(domain, 'TXT')

                for record in spf_records:
                    if str(record).lower().startswith('"v=spf'):
                        spf = str(record)  # Convert the DNS response to a string and check for "v=spf"
                        break

                # Check if spf is still an empty string after the loop (this covers the case where there are no TXT records or none of them start with 'v=spf')
                if not spf and len(spf_records) > 0:  # If there were TXT records, but no matching SPF one was found
                    spf = 'Not found'

                ## TLSA
                tlsa = get_tlsa_records(domain, ['192.168.10.1'])

                dmarc = get_records('_dmarc.' + domain, 'TXT')
                mta_sts = get_records('_mta-sts.' + domain, 'TXT')
                ipv4_mta_sts = get_records('mta-sts.' + domain, 'A')
                ipv6_mta_sts = get_records('mta-sts.' + domain, 'AAAA')
                mta_report = get_records('_smtp._tls.'  + domain, 'TXT')
                
                if ipv4_mta_sts:
                    mta_sts_txt = get_mta_sts_txt(domain)
                else:
                    mta_sts_txt = ''

                dnssec = IsDNSSEC_signed(domain, ['192.168.10.1'])

                for record in mx_records:
                    writer.writerow({'domain': domain, 'dnssec': dnssec, 'mx': str(record), 'caA': caA, 'spf': spf, 'dmarc': dmarc, 'mta-sts': mta_sts, 'ipv4-mta-sts': ipv4_mta_sts, 'ipv6-mta-sts': ipv6_mta_sts, 'mta-report': mta_report, 'tlsa': tlsa, 'mta_sts_txt': mta_sts_txt})
            except dns.resolver.NoAnswer:
                writer.writerow({'domain': domain, dnssec: 'No', 'mx': 'No MX records found', 'caA': get_records(domain, 'CAA'), 'spf': 'Not found', 'dmarc': 'Not found', 'mta-sts': 'Not found', 'ipv4-mta-sts': 'Not found', 'ipv6-mta-sts': 'Not found', 'mta-report': 'Not found', 'tlsa': 'Not found', 'mta_sts_txt': 'Not found'})
            except dns.resolver.NXDOMAIN:
                writer.writerow({'domain': domain, dnssec: 'No', 'mx': 'No MX records found', 'caA': get_records(domain, 'CAA'), 'spf': 'Not found', 'dmarc': 'Not found', 'mta-sts': 'Not found', 'ipv4-mta-sts': 'Not found', 'ipv6-mta-sts': 'Not found', 'mta-report': 'Not found', 'tlsa': 'Not found', 'mta_sts_txt': 'Not found'})

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print('Usage: python get_smtp_security_settings.py domains.txt mx_records.csv nameserver')
        sys.exit(1)

    domains = [line.strip() for line in open(sys.argv[1])]
    output_file = sys.argv[2]
    local_nameserver = [sys.argv[3]]

    get_mx_records(domains, output_file, local_nameserver)