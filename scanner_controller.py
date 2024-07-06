import tkinter as tk
from tkinter import filedialog

from scanner_model import ScannerModel
from scanner_view import ScannerView
import threading
import time
import os
from datetime import datetime


class ScannerController:
    def __init__(self, root):
        self.model = ScannerModel()
        self.view = ScannerView(root, self)
        self.domain_name = ""
        self.scheduled_scans = []
        self.current_scan_results = {}  # chatGPT: Store current scan results separately
        self.scan_thread = threading.Thread()
        self.stop_scan_flag = False

        self.monitor_thread = threading.Thread(target=self.monitor_scheduled_scans)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def show_scan_frame(self):
        self.view.scan_frame.pack(fill=tk.BOTH, expand=True)
        self.view.previous_scans_frame.pack_forget()
        self.view.scheduled_scans_frame.pack_forget()

    def show_previous_scans_frame(self):
        self.view.scan_frame.pack_forget()
        self.view.previous_scans_frame.pack(fill=tk.BOTH, expand=True)
        self.view.scheduled_scans_frame.pack_forget()
        self.load_previous_scans()

    def show_scheduled_scan_frame(self):
        self.view.scan_frame.pack_forget()
        self.view.previous_scans_frame.pack_forget()
        self.view.scheduled_scans_frame.pack(fill=tk.BOTH, expand=True)

    def start_scan_wrapper(self):
        self.domain_name = self.view.domain_entry.get()
        port_range = self.view.port_entry.get()
        if port_range == "":
            port_range = "1-1024"
        bruteforce = self.view.bruteforce_var.get()
        self.view.subdomain_listbox.delete(0, tk.END)

        if not self.model.check_domain_validity(self.domain_name):
            self.view.status_label.config(text="Invalid domain name")
            return

        if not self.model.validate_port_range(port_range):
            self.view.status_label.config(text="Invalid port range")
            return

        filename = f"{self.domain_name}_{port_range}_bruteforce={bruteforce}.json"
        if os.path.exists(os.path.join("subdomains", filename)):
            self.view.status_label.config(text="Loading existing scan results...")
            subdomain_ports = self.model.load_from_json(os.path.join("subdomains", filename))
            self.current_scan_results = subdomain_ports  # Store results separately
            self.populate_subdomain_list(subdomain_ports)
            self.view.status_label.config(text="Loaded existing scan results.")
            return

        self.view.status_label.config(text="Scanning started...")
        self.view.scan_button.config(state=tk.DISABLED)
        self.view.stop_button.config(state=tk.NORMAL)

        self.stop_scan_flag = False
        self.scan_thread = threading.Thread(target=self.start_scan,
                                            args=(self.domain_name, port_range, bruteforce),
                                            daemon=True)
        self.scan_thread.start()

    def on_save_as_pdf(self):
        if not self.current_scan_results:
            self.view.status_label.config(text="No scan results to generate report.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                                 filetypes=[("PDF files", "*.pdf")])
        if file_path:
            self.model.generate_pdf_report(self.current_scan_results, file_path)
            self.view.status_label.config(text=f"Report saved to {file_path}")

    def start_scan(self, domain_name, port_range, bruteforce):
        self.model.write_log_message("Starting subdomain scanning...\n", domain_name)
        subdomains = self.model.run_sublist3r(domain_name, bruteforce)
        self.view.progress_bar["maximum"] = len(subdomains)
        subdomain_data = {}

        subdomain_count = len(subdomains)
        self.model.write_log_message(f"{subdomain_count} subdomains found\n", domain_name)

        valid_no = 0

        for i in range(subdomain_count):
            if self.stop_scan_flag:  # Check if the stop flag is set
                self.view.subdomain_listbox.delete(0, tk.END)
                break  # Exit the loop if the scan is stopped

            subdomain = subdomains[i]

            progress_value = ((i + 1) / subdomain_count) * 100
            self.view.progress_bar["value"] = i + 1
            self.view.progress_percentage.config(text=f"{progress_value:.2f}%")
            self.view.master.update_idletasks()

            if self.model.check_domain_validity(subdomain):
                self.model.write_log_message(f"Valid subdomain : {subdomain}\n", domain_name)
                valid_no += 1
            else:
                self.model.write_log_message(f"Invalid subdomain : {subdomain}\n", domain_name)
                continue

            ip_address = self.model.get_ip(subdomain)
            self.model.write_log_message(f"Ip of the {subdomain} : {ip_address}\n", domain_name)
            open_ports = self.model.scan_ports(ip_address, port_range)
            self.model.write_log_message(f"Open Ports at the {ip_address} : {open_ports}\n", domain_name)

            self.model.write_log_message(f"Checking for an SSL certificate...\n", domain_name)
            ssl_details = self.model.fetch_ssl_details(subdomain)
            self.model.write_log_message(f"SSL details found for: {subdomain}\n", domain_name)

            subdomain_data[subdomain] = {
                "ip_address": ip_address,
                "open_ports": open_ports,
                "ssl_details": ssl_details
            }

            subdomain_info = f"{subdomain} ({len(open_ports)} open ports)"
            self.view.subdomain_listbox.insert(tk.END, subdomain_info)

        self.view.scan_button.config(state=tk.NORMAL)
        self.view.stop_button.config(state=tk.DISABLED)

        if not self.stop_scan_flag:  # Only save results if the scan wasn't stopped
            filename = f"{domain_name}_{port_range}_bruteforce={bruteforce}.json"
            self.model.save_to_json(os.path.join("subdomains", filename), subdomain_data)
            self.model.write_log_message(f"Found {valid_no} valid subdomains!\n", domain_name)
            self.model.write_log_message(f"Scan complete. Saved results to {filename}\n", domain_name)
            self.view.status_label.config(text="Scan complete.")
        else:
            self.model.write_log_message("Scan stopped by user\n", domain_name)
            self.view.status_label.config(text="Scan stopped by user.")

        self.view.progress_bar["value"] = 0
        self.view.progress_percentage.config(text="0%")
        self.current_scan_results = subdomain_data

    def stop_scan(self):
        self.model.write_log_message("Stopping the operation...\n", self.domain_name)
        self.stop_scan_flag = True

        self.view.scan_button.config(state=tk.NORMAL)

        self.view.stop_button.config(state=tk.DISABLED)

        self.view.status_label.config(text="Scanning stopped by user.")

        self.model.write_log_message("Operation stopped\n", self.domain_name)

    def show_subdomain_details(self, event):
        selection = self.view.subdomain_listbox.curselection()
        if selection:
            subdomain = self.view.subdomain_listbox.get(selection[0]).split(" ")[0]
            details = self.current_scan_results.get(subdomain, {})
            self.open_subdomain_details_window(subdomain, details)

    def open_subdomain_details_window(self, subdomain, details):
        details_window = tk.Toplevel(self.view.master, pady=15, padx=15)
        details_window.title(f"Details for {subdomain}")

        # Use a frame for better layout control
        details_frame = tk.Frame(details_window, padx=10, pady=10)
        details_frame.pack(fill=tk.BOTH, expand=True)

        # Styling options
        label_font = ("Arial", 12)
        label_font_bold = ("Arial", 12, "bold")

        ip_label = tk.Label(details_frame, text=f"IP Address: ", font=label_font_bold)
        ip_value = tk.Label(details_frame, text=f"{details['ip_address']}", font=label_font)
        ip_label.grid(row=0, column=0, sticky=tk.W, pady=5)
        ip_value.grid(row=0, column=1, sticky=tk.W, pady=5)

        ports_label = tk.Label(details_frame, text="Open Ports: ", font=label_font_bold)
        ports_value = tk.Label(details_frame, text=f"{', '.join(map(str, details['open_ports']))}", font=label_font)
        ports_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        ports_value.grid(row=1, column=1, sticky=tk.W, pady=5)

        if details['ssl_details']:
            ssl_button = tk.Button(details_frame, text="Show SSL Details",
                                   command=lambda: self.open_ssl_details_window(details['ssl_details']))
            ssl_button.grid(row=2, columnspan=2, pady=10)
        else:
            ssl_info = tk.Label(details_frame, text="[No SSL certificate found]", font=label_font)
            ssl_info.grid(row=2, columnspan=2, pady=10)

    def open_ssl_details_window(self, ssl_details):
        ssl_window = tk.Toplevel(self.view.master, pady=15, padx=15)
        ssl_window.title("SSL Certificate Details")

        # Use a frame for better layout control
        ssl_frame = tk.Frame(ssl_window, padx=10, pady=10)
        ssl_frame.pack(fill=tk.BOTH, expand=True)

        # Styling options
        label_font = ("Arial", 12)
        label_font_bold = ("Arial", 12, "bold")

        def add_ssl_detail(row, label, value):
            label_widget = tk.Label(ssl_frame, text=label, font=label_font_bold)
            value_widget = tk.Label(ssl_frame, text=value, font=label_font)
            label_widget.grid(row=row, column=0, sticky=tk.W, pady=5)
            value_widget.grid(row=row, column=1, sticky=tk.W, pady=5)

        add_ssl_detail(0, "Subject:", ssl_details['subject'][0][0][1])
        add_ssl_detail(1, "Issuer(Country, Province, Locality)",
                       (f"{ssl_details['issuer'][0][0][1]}, "
                        f"{ssl_details['issuer'][1][0][1]}, "
                        f"{ssl_details['issuer'][2][0][1]}"))

        add_ssl_detail(2, "Version:", ssl_details['version'])
        add_ssl_detail(3, "Serial Number:", ssl_details['serialNumber'])
        add_ssl_detail(4, "Validity:", f"{ssl_details['notBefore']} - {ssl_details['notAfter']}")
        add_ssl_detail(5, "OCSP:", ssl_details['OCSP'][0])
        add_ssl_detail(6, "caIssuers:", ssl_details['caIssuers'][0])

        # Subject Alt Names
        subject_alt_names_label = tk.Label(ssl_frame, text="Subject Alt Names:", font=label_font_bold)
        subject_alt_names_label.grid(row=7, column=0, sticky=tk.W, pady=5)
        for i, alt_name in enumerate(ssl_details['subjectAltName'], start=8):
            alt_name_label = tk.Label(ssl_frame, text=alt_name[1], font=label_font)
            alt_name_label.grid(row=i, column=1, sticky=tk.W, pady=2)

    def load_previous_scans(self):
        self.view.previous_scans_listbox.delete(0, tk.END)
        for file in os.listdir("subdomains"):
            if file.endswith(".json"):
                self.view.previous_scans_listbox.insert(tk.END, file)

    def load_selected_scan(self, event):
        selection = self.view.previous_scans_listbox.curselection()
        if selection:
            filename = self.view.previous_scans_listbox.get(selection[0])
            domain_name = filename.split("_")[0]
            self.domain_name = domain_name

            self.view.status_label.config(text="Loading existing scan results...")
            subdomain_ports = self.model.load_from_json(os.path.join("subdomains", filename))
            self.current_scan_results = subdomain_ports  # chatGPT: Store results separately

            self.view.subdomain_listbox.delete(0, tk.END)
            self.populate_subdomain_list(subdomain_ports)

            self.show_scan_frame()
            self.view.status_label.config(text="Loaded existing scan results.")
            self.view.previous_scans_status_label.config(text=f"Loaded: {filename}")

    def schedule_scan(self):
        domain_name = self.view.schedule_domain_entry.get()
        port_range = self.view.schedule_port_entry.get()
        if port_range == "":
            port_range = "1-1024"
        bruteforce = self.view.schedule_bruteforce_var.get()
        if self.view.entry1_disabled and not self.view.entry2_disabled:
            schedule_time_str = (self.view.day_entry.get() + "-" +
                                 self.view.month_entry.get() + "-" +
                                 self.view.year_entry.get() + " " +
                                 self.view.hour_entry.get() + ":" +
                                 self.view.minute_entry.get() + ":" +
                                 self.view.second_entry.get())
        else:
            schedule_time_str = self.model.addSecs(datetime.now().time(), int(self.view.start_after_x_seconds_entry))

        if schedule_time_str == "":
            self.view.scheduled_status_label.config(text="Please enter a valid schedule time.")
            return

        try:
            schedule_time = datetime.strptime(schedule_time_str, "%d-%m-%Y %H:%M:%S")
        except ValueError as e:
            self.view.scheduled_status_label.config(text=f"Error parsing schedule time: {e}")
            return

        self.scheduled_scans.append({
            "domain_name": domain_name,
            "port_range": port_range,
            "bruteforce": bruteforce,
            "schedule_time": schedule_time
        })
        self.view.schedule_listbox.insert(tk.END, f"{domain_name} at {schedule_time_str}")

    def monitor_scheduled_scans(self):
        while True:
            current_time = datetime.now()
            for scan in self.scheduled_scans[:]:  # Iterate over a copy of the list
                if current_time >= scan["schedule_time"]:
                    domain_name = scan["domain_name"]
                    port_range = scan["port_range"]
                    bruteforce = scan["bruteforce"]
                    self.view.subdomain_listbox.delete(0, tk.END)
                    self.start_scan(domain_name, port_range, bruteforce)
                    self.scheduled_scans.remove(scan)
            time.sleep(1)  # Sleep for a short time to reduce CPU usage

    def populate_subdomain_list(self, subdomain_ports):
        for subdomain, data in subdomain_ports.items():
            subdomain_info = f"{subdomain} ({len(data['open_ports'])} open ports)"
            self.view.subdomain_listbox.insert(tk.END, subdomain_info)

    def show_log_detail(self):
        log_details_window = tk.Toplevel(self.view.master, pady=15, padx=15)
        log_details_window.title(f"Details for {self.domain_name}")
        log_details_window.geometry("1000x750")

        log_details_scrollable = tk.Listbox(log_details_window)

        # Styling options
        label_font = ("Arial", 12)
        try:
            log_details_scrollable.pack(fill=tk.BOTH, expand=True, font=label_font)
            with open(f'logs/{self.domain_name}.log', 'r') as logs:
                for log in logs:
                    print(log)
                    log_details_scrollable.insert(tk.END, log)
        except FileNotFoundError as error:
            log_details_window.destroy()
            error_message_window = tk.Toplevel(self.view.master, padx=15, pady=15)
            error_message_window.title("Error!")
            error_message = tk.Label(error_message_window, text=f"Log for the domain not found:\n{error}")
            error_message.pack(fill=tk.BOTH, expand=True, font=label_font)

    def enable_entry1(self):
        self.view.entry1_disabled = False
        self.view.entry2_disabled = True
        self.view.start_after_x_seconds_entry.config(state="normal")  # Enable entry when a radio button is selected

    def enable_entry2(self):
        self.view.entry2_disabled = False
        self.view.entry1_disabled = True
        self.view.day_entry.config(state="normal")
        self.view.month_entry.config(state="normal")
        self.view.year_entry.config(state="normal")
        self.view.hour_entry.config(state="normal")
        self.view.minute_entry.config(state="normal")
        self.view.second_entry.config(state="normal")
