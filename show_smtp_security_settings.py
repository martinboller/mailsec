import csv
import curses
import sys
import datetime
import os
# Get the exact directory where your script lives
script_dir = os.path.dirname(os.path.abspath(__file__))
log_path = os.path.join(script_dir, "dns_debug.log")

# Function to read CSV and return data
def read_csv(file_path):
    try:
        with open(file_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            data = list(reader)
        return data
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
        return []
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        return []

# Traffic light mapping: (color_pair_id, symbol)
traffic_lights = {
    True: (1, '✓'),  # Green checkmark
    False: (2, '✗') # Red circle-x mark
}

# Helper to calculate column widths dynamically
def calculate_widths(data):
    all_columns = set()
    for item in data:
        all_columns.update(item.keys())
    columns = sorted(list(all_columns - {'domain'}))
    header_row = ['Domain'] + columns

    column_widths = {}
    for col in header_row:
        max_w = len(col)
        for item in data:
            val = item.get(col if col != 'Domain' else 'domain', '')
            display_val = str(val) if col.lower() == 'dnssec' else ('✓' if col != 'Domain' else val)
            if len(display_val) > max_w:
                max_w = len(display_val)
        column_widths[col] = max_w
    return columns, header_row, column_widths

# --- Documentation Subscreen ---
def show_info_screen(stdscr):
    stdscr.clear()
    
    info_data = [
        ("domain", "Input Data", "Base domain undergoing security analysis from the csv file with domains"),
        ("dnssec", "DNSKEY", "Confirms if zone is signed (True/False). If False, TLSA and MTA-STS is untrusted."),
        ("mx", "MX Record", "Mail Exchanger: Points to servers handling inbound mail."),
        ("caA", "CAA Record", "Declares which Certificate Authorities may issue TLS certs."),
        ("spf", "TXT Record", "Sender Policy Framework: Lists IPs authorized to send mail."),
        ("dmarc", "TXT Record", "Policy instructing receivers what to do if SPF or DKIM fails."),
        ("mta-sts", "TXT Record", "Signals that the domain supports and enforces TLS encryption."),
        ("ipv4-mta-sts", "A Record", "Resolves the HTTPS policy host to an IPv4 endpoint."),
        ("ipv6-mta-sts", "AAAA Record", "Resolves the HTTPS policy host to an IPv6 endpoint."),
        ("mta-report", "TXT Record", "TLS Reporting: URI endpoint where daily diagnostic reports are sent."),
        ("tlsa", "TLSA Records", "DANE Protocol: Pins specific public keys directly to your DNS layer."),
        ("mta_sts_txt", "HTTPS Fetch", "The raw plaintext MTA-STS policy file fetched via HTTPS.")
    ]

    stdscr.addstr(0, 0, " === SMTP SECURITY CONTROLS DICTIONARY ===", curses.A_BOLD | curses.A_REVERSE)
    stdscr.addstr(1, 0, f"{'Field Name':<15} | {'Source Type':<13} | {'Purpose & Technical Explanation'}")
    stdscr.addstr(15, 0, "Note: Data is only verified for availability, the actual setting is not analyzed in detail.", curses.A_BOLD)   
    stdscr.addstr(2, 0, "-" * 80)

    for idx, (field, src, desc) in enumerate(info_data, start=3):
        stdscr.addstr(idx, 0, f"{field:<15}", curses.A_BOLD)
        stdscr.addstr(idx, 15, f" | {src:<13} | {desc}")

    stdscr.addstr(len(info_data) + 5, 0, "Press any key to return to dashboard...", curses.A_BLINK)
    stdscr.refresh()
    stdscr.getch()

# --- Export Functions ---
def export_to_html(data, columns, header_row):
    filename = "report.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("""<!DOCTYPE html><html><head><style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; }
        table { border-collapse: collapse; width: 100%; background: #fff; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #dddddd; text-align: left; padding: 12px; }
        th { background-color: #333; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .center { text-align: center; font-weight: bold; }
        .pass { color: #2ecc71; }
        .fail { color: #e74c3c; }
        </style></head><body><h2>SMTP Security Status Report</h2><table><tr>""")
        for col in header_row:
            f.write(f"<th>{col}</th>\n")
        f.write("</tr>\n")
        for item in data:
            f.write("<tr>")
            f.write(f"<td>{item.get('domain', '')}</td>")
            for key in columns:
                val = item.get(key, '')
                status = bool(val and val != 'False')
                symbol, cls = ('✓', 'pass') if status else ('✗', 'fail')
                f.write(f"<td class='center {cls}'>{symbol}</td>")
            f.write("</tr>\n")
        f.write("</table></body></html>")
    return filename

def export_to_pdf(data, columns, header_row):
    try:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
    except ImportError:
        return "Error: fpdf2 library missing. Run 'pip install fpdf2'"

    filename = "report.pdf"
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.add_page(orientation="L")
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "SMTP Security Status Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
    pdf.ln(4)

    usable_width = 275
    max_domain_chars = max(max(len(item.get('domain', '')) for item in data), 12)
    domain_width = (max_domain_chars * 2.1) + 6
    if domain_width > 100: domain_width = 100

    remaining_width = usable_width - domain_width
    status_col_width = remaining_width / len(columns)
    pdf_widths = {col: status_col_width for col in columns}
    pdf_widths['Domain'] = domain_width

    pdf.set_font("Helvetica", "B", 8)
    start_y = pdf.get_y()
    max_header_height = 8
    for col in header_row:
        pdf.multi_cell(pdf_widths[col], max_header_height, col, border=1, align="C", new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_y(start_y + max_header_height)
    pdf.cell(0, 0, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    for item in data:
        domain_text = f"  {item.get('domain', '')}"
        pdf.cell(pdf_widths['Domain'], 7, domain_text, border=1, align="L")
        for key in columns:
            value = item.get(key, '')
            status = bool(value and value != 'False')
            if status:
                pdf.set_text_color(46, 204, 113)
                symbol = "Y"
            else:
                pdf.set_text_color(231, 76, 60)
                symbol = "X"
            pdf.cell(pdf_widths[key], 7, symbol, border=1, align="C")
            pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 7, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.output(filename)
    return filename

import datetime

def export_to_markdown(data, columns, header_row):
    filename = "report.md"
    
    # Capture the exact current timestamp in ISO 8601 format with UTC 'Z' marker
    current_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    with open(filename, "w", encoding="utf-8") as f:
        # Hugo Front Matter Configuration with dynamic execution time
        f.write("---\n")
        f.write("title: \"SMTP Security Settings Report\"\n")
        f.write(f"date: {current_timestamp}\n")
        f.write("draft: false\n")
        f.write("---\n\n")
        f.write("## SMTP security settings for scanned domains\n")

        # Render Markdown Table Headers
        f.write("| " + " | ".join(header_row) + " |\n")
        
        # Render Markdown Separator alignment row
        separator_row = ["| :--- "] + [" :---: " for _ in columns]
        f.write("|".join(separator_row) + "|\n")
        
        # Render Markdown Data Rows (Explicit loop verification)
        for item in data:
            row_cells = []
            # Append the current domain text safely
            row_cells.append(item.get('domain', ''))
            
            # Loop through the security metrics for this specific domain
            # Debug 
            is_ravendo = any("ravendo" in str(v).lower() for v in item.values()) or "ravendo.dk" in str(item.values())

            for key in columns:
                val = item.get(key, '')
                val_str = str(val).strip()
                is_null_mx = val_str == '0 .' or val_str == '.'
                status = bool(val_str) and val_str.lower() not in ['False', ''] and not is_null_mx
                # If it's Ravendo, FORCE print directly to your terminal screen
                # This bypasses all file write/path bugs completely
                if is_ravendo:
                    print(f"\n!!! SCREEN DEBUG FOR RAVENDO !!!")
                    print(f"Column Key    : '{key}'")
                    print(f"Value Found   : '{val_str}'")
                    print(f"Status Result : {status}")
                    print(f"Symbol Used   : {'✓' if status else '✗'}")

                if not status:
                    try:
                        with open(log_path, "a", encoding="utf-8") as f:
                            f.write(f"--- FAILED CHECK FOR DOMAIN/KEY ---\n")
                            f.write(f"Key used for lookup : '{key}'\n")
                            f.write(f"Stringified Value   : '{val_str}'\n\n")
                    except Exception as e:
                        print(f"Could not write log file: {e}")

                row_cells.append("✓" if status else "✗")
                
            # Write out this complete domain row before moving to the next one
            f.write("| " + " | ".join(row_cells) + " |\n")
            
        # Append the Explanations Reference Table
        f.write("\n\n## DNS Security Controls Reference Dictionary\n\n")
        f.write("| Field Name | Source / Record Type | Target Format / Values | Purpose & Technical Explanation |\n")
        f.write("| :--- | :--- | :--- | :--- |\n")
        f.write("| **domain** | Input Data | String (e.g., `example.com`) | The base domain environment undergoing security analysis. |\n")
        f.write("| **dnssec** | DNS Cryptographic Check (`DNSKEY`) | `True` or `False` | Confirms whether the domain's DNS zone is cryptographically signed. If `False`, records like TLSA cannot be trusted securely. |\n")
        f.write("| **mx** | `MX` Record | Text String (Priority + Host) | **Mail Exchanger:** Points to the mail server(s) responsible for accepting inbound email for the domain. |\n")
        f.write("| **CAA** | `CAA` Record | Text String | **Certification Authority Authorization:** Declares which Certificate Authorities (CAs) are officially allowed to issue SSL/TLS certificates for this domain. |\n")
        f.write("| **spf** | `TXT` Record (starting with `v=spf1`) | Text String | **Sender Policy Framework:** A hardcoded list of authorized IP addresses and servers allowed to send outbound mail on behalf of the domain to prevent spoofing. |\n")
        f.write("| **dmarc** | `TXT` Record (`_dmarc.domain`) | Text String | **Domain-based Message Authentication, Reporting, and Conformance:** Tie-breaker policy that instructs receivers what to do (none, quarantine, reject) if SPF or DKIM fails. |\n")
        f.write("| **mta-sts** | `TXT` Record (`_mta-sts.domain`) | Text String | **MTA Strict Transport Security (DNS):** A signal record containing a policy version and id (timestamp). Tells sending servers that this domain supports and enforces TLS encryption. |\n")
        f.write("| **ipv4-mta-sts** | `A` Record (`mta-sts.domain`) | IPv4 Address | Resolves the dedicated host serving the MTA-STS policy file via HTTPS to an IPv4 endpoint. |\n")
        f.write("| **ipv6-mta-sts** | `AAAA` Record (`mta-sts.domain`) | IPv6 Address | Resolves the dedicated host serving the MTA-STS policy file via HTTPS to an IPv6 endpoint. |\n")
        f.write("| **mta-report** | `TXT` Record (`_smtp._tls.domain`) | Text String | **TLS Reporting (TLS-RPT):** Configures an email address or URI endpoint where sending mail servers can transmit daily diagnostic reports about TLS connection successes or failures. |\n")
        f.write("| **tlsa** | `TLSA` Records (Ports 25, 465, 587, etc.) | List of Hex Fingerprints | **DANE Protocol:** Pins a specific certificate public key directly to your DNS layer. This prevents Man-in-the-Middle (MitM) attacks by guaranteeing the exact certificate the mail server must use. |\n")
        f.write("| **mta_sts_txt** | HTTPS Web Fetch (`/.well-known/mta-sts.txt`) | Raw File Contents | **MTA-STS Policy File:** A plaintext file hosted via strict HTTPS that defines your encryption constraints (`enforce`, `testing`, or `none`), specifies valid MX hosts, and sets a max age cache parameter. |\n")
            
    return filename

# --- Core TUI Layout ---
def display_tui(data, stdscr):
    columns, header_row, column_widths = calculate_widths(data)
    
    # Initialize scrolling variables
    current_scroll_row = 0
    stdscr.keypad(True) # Required to capture Up/Down arrow keys correctly

    while True:
        stdscr.clear()
        curses.curs_set(0)
        max_y, max_x = stdscr.getmaxyx()

        # Action Menu Header
        menu_str = " [Q] Quit   [I] Field Info   [H] Export HTML   [P] Export PDF   [M] Export Markdown"
        stdscr.addstr(0, 0, menu_str[:max_x], curses.A_REVERSE)

        # Format and print Data Headers
        formatted_header = " | ".join(f"{col:<{column_widths[col]}}" for col in header_row)
        stdscr.addstr(2, 0, formatted_header[:max_x], curses.A_BOLD)

        # Calculate workspace dimensions
        header_height = 3
        # Max rows available on screen for data items
        visible_data_rows = max_y - header_height - 1 

        # Slice the dataset to fit within the current window offset viewport
        visible_items = data[current_scroll_row : current_scroll_row + visible_data_rows]

        # Format and print the visible Data Rows
        row = header_height
        for item in visible_items:
            if row >= max_y - 1:
                break

            domain_val = item.get('domain', '')
            stdscr.addstr(row, 0, f"{domain_val:<{column_widths['Domain']}}")
            current_x = column_widths['Domain']

            for key in columns:
                if current_x + 3 >= max_x:
                    break
                stdscr.addstr(row, current_x, " | ")
                current_x += 3               
                
                # --- FIXED DATA RETRIEVAL & NORMALIZATION ---
                value = item.get(key, '')
                val_str = str(value).strip()
                
                # Check for RFC 7505 Null MX record ("0 .")
                is_null_mx = val_str == '0 .' or val_str == '.'
                
                # Robust validation logic matching your HTML export
                status = bool(val_str) and val_str.lower() not in ['false', ''] and not is_null_mx
                # --------------------------------------------
                    
                if current_x + column_widths[key] >= max_x:
                    break
                    
                color_idx, symbol = traffic_lights[status]
                padded_symbol = f"{symbol:^{column_widths[key]}}"
                stdscr.addstr(row, current_x, padded_symbol, curses.color_pair(color_idx))
                current_x += column_widths[key]
            row += 1

        # Safe scrolling indicator bar (Using row index 1 to completely avoid the bottom-right crash zone)
        if len(data) > visible_data_rows and visible_data_rows > 0:
            indicator = f"Showing rows {current_scroll_row + 1}-{min(current_scroll_row + visible_data_rows, len(data))} of {len(data)} (Use arrows/j/k to scroll)"
            stdscr.addstr(1, 0, indicator[:max_x], curses.A_DIM)
            
        # 5. Interactive Navigation Input Listener
        ch = stdscr.getch()
        
        if ch in (ord('q'), ord('Q')):
            break
        elif ch in (ord('i'), ord('I')):
            show_info_screen(stdscr)
        elif ch in (ord('h'), ord('H')):
            outfile = export_to_html(data, columns, header_row)
            stdscr.addstr(max_y - 1, 0, f"Saved to {outfile}! Key...", curses.A_BLINK)
            stdscr.getch()
        elif ch in (ord('p'), ord('P')):
            outfile = export_to_pdf(data, columns, header_row)
            stdscr.addstr(max_y - 1, 0, f"Saved to {outfile}! Key...", curses.A_BLINK)
            stdscr.getch()
        elif ch in (ord('m'), ord('M')):
            outfile = export_to_markdown(data, columns, header_row)
            stdscr.addstr(max_y - 1, 0, f"Saved to {outfile}! Key...", curses.A_BLINK)
            stdscr.getch()
            
        # Scroll controls: Arrow keys or Vim keybindings (j=down, k=up)
        elif ch in (curses.KEY_DOWN, ord('j'), ord('J')):
            if current_scroll_row < len(data) - visible_data_rows:
                current_scroll_row += 1
        elif ch in (curses.KEY_UP, ord('k'), ord('K')):
            if current_scroll_row > 0:
                current_scroll_row -= 1

def main():
    if len(sys.argv) < 2:
        print("Usage: python show_smtp_settings.py <path_to_csv_file>")
        sys.exit(1)

    csv_file_path = sys.argv[1]
    raw_data = read_csv(csv_file_path)

    if not raw_data: 
        return

    # --- DEDUPLICATION LOGIC ---
    # Keep only the very first instance of each domain
    seen_domains = set()
    data = []
    for item in raw_data:
        domain = item.get('domain', '').strip().lower()
        if domain not in seen_domains:
            seen_domains.add(domain)
            data.append(item)
    # ----------------------------

    def curses_main(stdscr):
        if curses.has_colors():
            curses.start_color()
            curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
            curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        else:
            global traffic_lights
            traffic_lights = {True: (0, '✓'), False: (0, '✗')}
        display_tui(data, stdscr)

    curses.wrapper(curses_main)

if __name__ == "__main__":
    main()