import csv
import curses
import sys

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
        </style></head><body><h2>MX Record Status Report</h2><table><tr>""")
        for col in header_row:
            f.write(f"<th>{col}</th>\n")
        f.write("</tr>\n")
        for item in data:
            f.write("<tr>")
            f.write(f"<td>{item.get('domain', '')}</td>")
            for key in columns:
                val = item.get(key, '')
                if key.lower() == 'dnssec':
                    f.write(f"<td>{val}</td>")
                else:
                    status = bool(val and val != 'Not found')
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
    pdf.cell(0, 10, "MX Record Status Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
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
            if key.lower() == 'dnssec':
                pdf.cell(pdf_widths[key], 7, f"  {str(value)}", border=1, align="L")
            else:
                status = bool(value and value != 'Not found')
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

def export_to_markdown(data, columns, header_row):
    filename = "report.md"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("---\ntitle: \"MX Record Status Report\"\ndate: 2026-06-27T10:43:00Z\ndraft: false\n---\n\n")
        f.write("| " + " | ".join(header_row) + " |\n")
        separator_row = ["| :--- "] + [" :---: " for _ in columns]
        f.write("|".join(separator_row) + "|\n")
        for item in data:
            row_cells = [item.get('domain', '')]
            for key in columns:
                val = item.get(key, '')
                if key.lower() == 'dnssec':
                    row_cells.append(str(val))
                else:
                    status = bool(val and val != 'Not found')
                    row_cells.append("✓" if status else "✗")
            f.write("| " + " | ".join(row_cells) + " |\n")
    return filename

# --- Core TUI Layout ---
def display_tui(data, stdscr):
    columns, header_row, column_widths = calculate_widths(data)

    while True:
        stdscr.clear()
        curses.curs_set(0)

        # 1. Action Menu Header (Updated with info trigger)
        menu_str = " [Q] Quit   [I] Field Info   [H] Export HTML   [P] Export PDF   [M] Export Markdown"
        stdscr.addstr(0, 0, menu_str, curses.A_REVERSE)

        # 2. Format and print Data Headers
        formatted_header = " | ".join(f"{col:<{column_widths[col]}}" for col in header_row)
        stdscr.addstr(2, 0, formatted_header, curses.A_BOLD)

        # 3. Format and print the Data Rows
        row = 3
        for item in data:
            domain_val = item.get('domain', '')
            stdscr.addstr(row, 0, f"{domain_val:<{column_widths['Domain']}}")
            current_x = column_widths['Domain']

            for key in columns:
                stdscr.addstr(row, current_x, " | ")
                current_x += 3 
                
                value = item.get(key, '')
                if key.lower() == 'dnssec':
                    padded_val = f"{str(value):<{column_widths[key]}}"
                    stdscr.addstr(row, current_x, padded_val)
                    current_x += column_widths[key]
                else:
                    status = bool(value and value != 'Not found')
                    color_idx, symbol = traffic_lights[status]
                    padded_symbol = f"{symbol:^{column_widths[key]}}"
                    stdscr.addstr(row, current_x, padded_symbol, curses.color_pair(color_idx))
                    current_x += column_widths[key]
            row += 1

        stdscr.refresh()

        # 4. Input Listener loop
        ch = stdscr.getch()
        if ch in (ord('q'), ord('Q')):
            break
        elif ch in (ord('i'), ord('I')):
            show_info_screen(stdscr)
        elif ch in (ord('h'), ord('H')):
            outfile = export_to_html(data, columns, header_row)
            stdscr.addstr(row + 1, 0, f"Exported successfully to {outfile}! Press any key...", curses.A_BLINK)
            stdscr.getch()
        elif ch in (ord('p'), ord('P')):
            outfile = export_to_pdf(data, columns, header_row)
            stdscr.addstr(row + 1, 0, f"Exported successfully to {outfile}! Press any key...", curses.A_BLINK)
            stdscr.getch()
        elif ch in (ord('m'), ord('M')):
            outfile = export_to_markdown(data, columns, header_row)
            stdscr.addstr(row + 1, 0, f"Exported successfully to {outfile}! Press any key...", curses.A_BLINK)
            stdscr.getch()

def main():
    if len(sys.argv) < 2:
        print("Usage: python show_smtp_settings.py <path_to_csv_file>")
        sys.exit(1)

    csv_file_path = sys.argv[1]
    data = read_csv(csv_file_path)

    if not data: return

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