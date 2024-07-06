import socket
import threading
import sublist3r
import json
import os
import ssl
from fpdf import FPDF
from datetime import datetime
from datetime import timedelta
import queue


class ScannerModel:
    def __init__(self):
        if not os.path.exists("subdomains"):
            os.makedirs("subdomains")

    def check_domain_validity(self, domain_name):
        try:
            socket.gethostbyname(domain_name)
            return True
        except socket.error:
            return False

    def validate_port_range(self, port_range):
        try:
            start, end = map(int, port_range.split('-'))
            is_valid = 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end
            return is_valid
        except ValueError:
            return False

    def run_sublist3r(self, domain_name, bruteforce):
        subdomains = sublist3r.main(domain_name, 40, None, ports=None, silent=False, verbose=False,
                                    enable_bruteforce=bruteforce, engines=None)
        return subdomains

    def get_ip(self, subdomain):
        try:
            ip_address = socket.gethostbyname(subdomain)
            return ip_address
        except socket.error:
            return None

    def generate_pdf_report(self, scan_data, filename):
        class PDFReport(FPDF):
            def header(self):
                self.set_font('Arial', 'B', 12)
                self.cell(0, 10, 'Subdomain Scan Report', 0, 1, 'C')

            def chapter_title(self, title):
                self.set_font('Arial', 'B', 12)
                self.cell(0, 10, title, 0, 1, 'L')
                self.ln(10)

            def chapter_body(self, body):
                self.set_font('Arial', '', 12)
                self.multi_cell(0, 10, body)
                self.ln()

        pdf = PDFReport()
        pdf.add_page()
        pdf.chapter_title('Scan Results')

        for subdomain, data in scan_data.items():
            body = f"Subdomain: {subdomain}\n"
            body += f"IP Address: {data['ip_address']}\n"
            body += f"Open Ports: {', '.join(map(str, data['open_ports']))}\n"
            if data['ssl_details']:
                body += "SSL Details:\n"
                body += f"  Subject: {data['ssl_details']['subject'][0][0][1]}\n"
                body += f"  Issuer: {data['ssl_details']['issuer'][0][0][1]}\n"
                body += f"  Version: {data['ssl_details']['version']}\n"
                body += f"  Serial Number: {data['ssl_details']['serialNumber']}\n"
                body += f"  Validity: {data['ssl_details']['notBefore']} - {data['ssl_details']['notAfter']}\n"
                body += f"  OCSP: {data['ssl_details']['OCSP'][0]}\n"
                body += f"  caIssuers: {data['ssl_details']['caIssuers'][0]}\n"
                body += "  Subject Alt Names:\n"
                for san in data['ssl_details']['subjectAltName']:
                    body += f"    {san[1]}\n"
            pdf.chapter_body(body)

        pdf.output(filename)

    def port_open(self, ip_address, port, result_queue):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip_address, port))
        sock.close()
        if result == 0:
            result_queue.put(port)

    def scan_ports(self, ip_address, port_range):
        open_ports = []
        start, end = map(int, port_range.split('-'))
        result_queue = queue.Queue()
        threads = []
        max_threads = 100  # Limit the number of concurrent threads

        for port in range(start, end + 1):
            if len(threads) >= max_threads:
                # Wait for threads to finish before creating more
                for thread in threads:
                    thread.join()
                threads = []

            thread = threading.Thread(target=self.port_open, args=(ip_address, port, result_queue))
            threads.append(thread)
            thread.start()

        # Ensure all remaining threads are finished
        for thread in threads:
            thread.join()

        # Collect results from the queue
        while not result_queue.empty():
            open_ports.append(result_queue.get())

        return open_ports

    def fetch_ssl_details(self, subdomain):
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=subdomain)
        try:
            conn.settimeout(3.0)
            conn.connect((subdomain, 443))
            ssl_info = conn.getpeercert()
            return ssl_info
        except socket.error:
            return None

    def save_to_json(self, filename, data):
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)

    def load_from_json(self, filename):
        with open(filename, 'r') as f:
            data = json.load(f)
        return data

    def write_log_message(self, message, domain_name):
        if not os.path.exists("logs"):
            os.makedirs("logs")
        log_filename = f"logs/{domain_name}.log"
        with open(log_filename, 'a') as log_file:
            log_file.write(f"{datetime.now().isoformat()} - {message}\n")

    def addSecs(self, tm, secs):
        fulldate = datetime(100, 1, 1, tm.hour, tm.minute, tm.second)
        fulldate = fulldate + timedelta(seconds=secs)
        return fulldate.time()


