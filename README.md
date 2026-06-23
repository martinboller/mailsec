# get_smtp_security_settings.py

A Python script that retrieves SMTP DNS Resource Records (and mta-sts.txt) for use in analyzing overall e-mail security across different domains.

Looks up: MX records, CAA records, SPF records, DMARC records, MTA-STS records, IPv4 and IPv6 MTA-STS records, the corresponding TLSA records (for specified SMTP ports), DNSSEC status, and the well-known MTA-STS TXT file for a given list of domains.

## Requirements

    Python 3.x
    dnspython library (pip install dnspython)
    requests library (pip install requests)

## Usage

The script expects three command-line arguments:

     A file containing a list of domains (one per line)
     The output CSV file to store the results
     A comma-separated list of DNS nameservers

## Example usage:
```bash
python get_smtp_security_settings.py domains.txt smtp_records.csv 192.0.2.8
```

In this example, it reads the list of domains from domains.txt, stores the results in a CSV file named smtp_records.csv, and uses custom DNS nameserver 192.0.2.8

### Output

The script will create a CSV file with the following columns:


    domain
    dnsssec: DNSSEC status (True/False)
    mx: MX record for the domain
    caA: CAA record
    spf: SPF record
    dmarc: DMARC record
    mta-sts: MTA-STS record
    ipv4-mta-sts: IPv4 MTA-STS record
    ipv6-mta-sts: IPv6 MTA-STS record  
    tlsa: List of matching TLSA records for all specified SMTP ports
    mta_sts_txt: Well-known MTA-STS TXT file content

If zone is not signed (DNSSEC True) then the  script does not check for mta and tlsa RRs as these require DNSSEC.

## License

This script is released under the MIT license.