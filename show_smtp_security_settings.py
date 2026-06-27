import csv
import curses
import sys

# read CSV and return data
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

# calculate column widths dynamically - helper
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
            display_val = '✓' if col != 'Domain' else val
            if len(display_val) > max_w:
                max_w = len(display_val)
        column_widths[col] = max_w
    return columns, header_row, column_widths

# Export to html and pdf

def export_to_html(data, columns, header_row):
    filename = "report.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("""<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; }
        table { border-collapse: collapse; width: 100%; background: #fff; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #dddddd; text-align: left; padding: 12px; }
        th { background-color: #333; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .center { text-align: center; font-weight: bold; }
        .pass { color: #2ecc71; }
        .fail { color: #e74c3c; }
    </style>
</head>
<body>
    <h2>MX Record Status Report</h2>
    <table>
        <tr>
""")
        for col in header_row:
            f.write(f"            <th>{col}</th>\n")
        f.write("        </tr>\n")

        for item in data:
            f.write("        <tr>\n")
            f.write(f"            <td>{item.get('domain', '')}</td>\n")
            for key in columns:
                val = item.get(key, '')
                status = bool(val and val != 'False')
                symbol, cls = ('✓', 'pass') if status else ('✗', 'fail')
                f.write(f"            <td class='center {cls}'>{symbol}</td>\n")
            f.write("        </tr>\n")
            
        f.write("    </table>\n</body>\n</html>")
    return filename


# PDF export function
def export_to_pdf(data, columns, header_row):
    try:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
    except ImportError:
        return "Error: fpdf2 library missing. Run 'pip install fpdf2'"

    filename = "report.pdf"
    
    # Setup Landscape
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.add_page(orientation="L")
    
    # dd Title
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "MX Record Status Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
    pdf.ln(4)

    # Math-Based Column calc (A4 Landscape usable width = 275mm)
    usable_width = 275
    
    # Find the character length of the longest domain name in the data
    # (Default to a minimum string length of 12 if data is short)
    max_domain_chars = max(max(len(item.get('domain', '')) for item in data), 12)
    
    # Convert character count to mm (approx 2.1mm per char in Helvetica 9pt)
    # Add +6mm for the padding spaces we insert ("  " at the start)
    domain_width = (max_domain_chars * 2.1) + 6
    
    # Cap the domain width so a ridiculously long domain doesn't crush the status columns
    if domain_width > 100:
        domain_width = 100
    
    # Split the remaining space evenly across all status columns
    remaining_width = usable_width - domain_width
    status_col_width = remaining_width / len(columns)
    
    pdf_widths = {col: status_col_width for col in columns}
    pdf_widths['Domain'] = domain_width

    # Render Table Header (Using multi_cell or auto-wrap styling)
    pdf.set_font("Helvetica", "B", 8)  # Dropped to 8pt so long headers fit
    
    # Temporary row trick to keep headers aligned if they wrap
    start_y = pdf.get_y()
    max_header_height = 8  # mm
    
    for col in header_row:
        current_x = pdf.get_x()
        # multi_cell allows long headers like ipv4-mta-sts to break into 2 lines cleanly
        pdf.multi_cell(pdf_widths[col], max_header_height, col, border=1, align="C", 
                       new_x=XPos.RIGHT, new_y=YPos.TOP)
        
    # Move cursor to the next data row line
    pdf.set_font("Helvetica", "", 8)
    pdf.set_y(start_y + max_header_height)
    pdf.cell(0, 0, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Render Data Rows
    for item in data:
        # Prevent clipping on extra long domain names by trimming or letting it fit 65mm
        domain_text = f"  {item.get('domain', '')}"
        pdf.cell(pdf_widths['Domain'], 7, domain_text, border=1, align="L")
        
        for key in columns:
            val = item.get(key, '')
            status = bool(val and val != 'False')
            
            if status:
                pdf.set_text_color(46, 204, 113) # Green
                symbol = "Y" 
            else:
                pdf.set_text_color(231, 76, 60) # Red
                symbol = "X"
                
            pdf.cell(pdf_widths[key], 7, symbol, border=1, align="C")
            pdf.set_text_color(0, 0, 0) # Reset color
            
        pdf.cell(0, 7, "", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.output(filename)
    return filename

# --- Core TUI Layout ---

def display_tui(data, stdscr):
    # Parse data dependencies
    columns, header_row, column_widths = calculate_widths(data)

    while True:
        stdscr.clear()
        curses.curs_set(0)

        # Action Menu Header
        menu_str = " [Q] Quit   [H] Export HTML   [P] Export PDF"
        stdscr.addstr(0, 0, menu_str, curses.A_REVERSE)

        # Format and print Data Headers (Offset by 2 rows down)
        formatted_header = " | ".join(f"{col:<{column_widths[col]}}" for col in header_row)
        stdscr.addstr(2, 0, formatted_header, curses.A_BOLD)

        # Format and print the Data Rows
        row = 3
        for item in data:
            domain_val = item.get('domain', '')
            stdscr.addstr(row, 0, f"{domain_val:<{column_widths['Domain']}}")
            current_x = column_widths['Domain']

            for key in columns:
                stdscr.addstr(row, current_x, " | ")
                current_x += 3 
                
                value = item.get(key, '')
                status = bool(value and value != 'False')
                color_idx, symbol = traffic_lights[status]
                
                padded_symbol = f"{symbol:^{column_widths[key]}}"
                stdscr.addstr(row, current_x, padded_symbol, curses.color_pair(color_idx))
                current_x += column_widths[key]
            row += 1

        stdscr.refresh()

        # Input Listener loop
        ch = stdscr.getch()
        if ch in (ord('q'), ord('Q')):
            break
        elif ch in (ord('h'), ord('H')):
            outfile = export_to_html(data, columns, header_row)
            stdscr.addstr(row + 1, 0, f"Exported successfully to {outfile}! Press any key...", curses.A_BLINK)
            stdscr.getch()
        elif ch in (ord('p'), ord('P')):
            outfile = export_to_pdf(data, columns, header_row)
            stdscr.addstr(row + 1, 0, f"Exported successfully to {outfile}! Press any key...", curses.A_BLINK)
            stdscr.getch()

# Main
def main():
    if len(sys.argv) < 2:
        print("Usage: python script_name.py <path_to_csv_file>")
        sys.exit(1)

    csv_file_path = sys.argv[1]
    data = read_csv(csv_file_path)

    if not data:
        return

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