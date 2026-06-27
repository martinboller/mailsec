# get_smtp_security_settings.py

A Python script that retrieves SMTP DNS Resource Records (and mta-sts.txt) for use in analyzing overall e-mail security across different domains.

Looks up: MX records, CAA records, SPF records, DMARC records, MTA-STS records, IPv4 and IPv6 MTA-STS records, the corresponding TLSA records (for specified SMTP ports), DNSSEC status, and the well-known MTA-STS TXT file for a given list of domains.

## Requirements

    Python 3.x
    dnspython library (pip install dnspython)
    requests library (pip install requests)
    
    for the show_smtp_security_settings.py script:
    fpdf2 library (pip install fpdf2)

## Usage

The script expects three command-line arguments:

     A file containing a list of domains (one per line)
     The output CSV file to store the results
     A comma-separated list of DNS nameservers

## Example usage:
```bash
python get_smtp_security_settings.py domains.csv smtp_records.csv 192.0.2.8
```

In this example, it reads the list of domains from domains.csv, stores the results in a CSV file named smtp_records.csv, and uses custom DNS nameserver 192.0.2.8

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


### TUI 

It can interpret the CSV file for you and provide an overview of the settings for the tested domains and can export to different formats.


```bash
python show_smtp_security_settings.py smtp_records.csv
```

In this example, it reads the results created with get_smtp_security_settings.py and stored in smtp_records.csv. From there you can either just take a glance at the missing settings or export to either HTML, Hugo Markdown, or PDF.

![TUI](/images/TUI.png)



## Explanation of Information retrieved

| Field Name | Source / Record Type | Target Format / Values | Purpose & Technical Explanation |
| :--- | :--- | :--- | :--- |
| **domain** | Input Data | String (e.g., `example.com`) | The base domain environment undergoing security analysis. |
| **dnssec** | DNS Cryptographic Check (`DNSKEY`) | `True` or `False` | Confirms whether the domain's DNS zone is cryptographically signed. If `False`, records like TLSA cannot be trusted securely. |
| **mx** | `MX` Record | Text String (Priority + Host) | **Mail Exchanger:** Points to the mail server(s) responsible for accepting inbound email for the domain. |
| **CAA** | `CAA` Record | Text String | **Certification Authority Authorization:** Declares which Certificate Authorities (CAs) are officially allowed to issue SSL/TLS certificates for this domain. |
| **spf** | `TXT` Record (starting with `v=spf1`) | Text String | **Sender Policy Framework:** A hardcoded list of authorized IP addresses and servers allowed to send outbound mail on behalf of the domain to prevent spoofing. |
| **dmarc** | `TXT` Record (`_dmarc.domain`) | Text String | **Domain-based Message Authentication, Reporting, and Conformance:** Tie-breaker policy that instructs receivers what to do (none, quarantine, reject) if SPF or DKIM fails. |
| **mta-sts** | `TXT` Record (`_mta-sts.domain`) | Text String | **MTA Strict Transport Security (DNS):** A signal record containing a policy version and id (timestamp). Tells sending servers that this domain supports and enforces TLS encryption. |
| **ipv4-mta-sts** | `A` Record (`mta-sts.domain`) | IPv4 Address | Resolves the dedicated host serving the MTA-STS policy file via HTTPS to an IPv4 endpoint. |
| **ipv6-mta-sts** | `AAAA` Record (`mta-sts.domain`) | IPv6 Address | Resolves the dedicated host serving the MTA-STS policy file via HTTPS to an IPv6 endpoint. |
| **mta-report** | `TXT` Record (`_smtp._tls.domain`) | Text String | **TLS Reporting (TLS-RPT):** Configures an email address or URI endpoint where sending mail servers can transmit daily diagnostic reports about TLS connection successes or failures. |
| **tlsa** | `TLSA` Records (Ports 25, 465, 587, etc.) | List of Hex Fingerprints | **DANE Protocol:** Pins a specific certificate public key directly to your DNS layer. This prevents Man-in-the-Middle (MitM) attacks by guaranteeing the exact certificate the mail server must use. |
| **mta_sts_txt** | HTTPS Web Fetch (`/.well-known/mta-sts.txt`) | Raw File Contents | **MTA-STS Policy File:** A plaintext file hosted via strict HTTPS that defines your encryption constraints (`enforce`, `testing`, or `none`), specifies valid MX hosts, and sets a max age cache parameter. |


## License

This script is released under the MIT license.