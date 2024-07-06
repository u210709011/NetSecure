from _datetime import datetime
import tkinter as tk
from tkinter import ttk, Menu


class ScannerView:
    def __init__(self, master, controller):
        self.master = master
        self.controller = controller
        self.master.title("Subdomain Scanner")
        self.master.geometry("800x600")
        self.master.configure(bg='#f0f0f0')

        self.style = ttk.Style()
        self.style.configure("TLabel", font=("Arial", 12))
        self.style.configure("TButton", font=("Arial", 12))
        self.style.configure("TCheckbutton", font=("Arial", 12))
        self.style.configure("TEntry", font=("Arial", 12))
        self.style.configure("TListbox", font=("Arial", 12))

        self.menu = Menu(master)
        master.config(menu=self.menu)

        self.menu.add_command(label="Start Scan", command=self.controller.show_scan_frame)
        self.menu.add_command(label="View Previous Scans", command=self.controller.show_previous_scans_frame)
        self.menu.add_command(label="Scheduled Scan", command=self.controller.show_scheduled_scan_frame)

        self.scan_frame = tk.Frame(master, bg='#f0f0f0')
        self.previous_scans_frame = tk.Frame(master, bg='#f0f0f0')
        self.scheduled_scans_frame = tk.Frame(master, bg='#f0f0f0')

        self.create_scan_frame()
        self.create_previous_scans_frame()
        self.create_scheduled_scan_frame()

        self.scan_frame.pack(fill=tk.BOTH, expand=True)

    def create_scan_frame(self):
        self.domain_frame = tk.Frame(self.scan_frame, pady=15, bg='#f0f0f0')
        self.domain_frame.pack()

        self.domain_label = ttk.Label(self.domain_frame, text="Enter domain name:")
        self.domain_label.pack(side=tk.LEFT, padx=5)

        self.domain_entry = ttk.Entry(self.domain_frame, width=50)
        self.domain_entry.pack(side=tk.LEFT, padx=5)

        self.scan_button = ttk.Button(self.domain_frame, text="Scan", command=self.controller.start_scan_wrapper)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_button_icon = tk.PhotoImage(file="stop_icon.png", height=21, width=20)
        self.stop_button = tk.Button(self.domain_frame, image=self.stop_button_icon, command=self.controller.stop_scan,
                                     state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.pdf_icon = tk.PhotoImage(file="save_pdf_icon.png", height=20, width=15)
        self.generate_report_button = tk.Button(self.domain_frame, image=self.pdf_icon,
                                                command=self.controller.on_save_as_pdf)
        self.generate_report_button.pack(side=tk.LEFT, padx=5)

        self.log_button = ttk.Button(self.domain_frame, text='log', command=self.controller.show_log_detail)
        self.log_button.pack(side=tk.LEFT, padx=5)

        self.option_frame = tk.Frame(self.scan_frame, pady=15, bg='#f0f0f0')
        self.option_frame.pack()

        self.port_label = ttk.Label(self.option_frame, text="Port range (default: 1-1024):")
        self.port_label.pack(side=tk.LEFT, padx=5)

        self.port_entry = ttk.Entry(self.option_frame, width=20)
        self.port_entry.pack(side=tk.LEFT, padx=5)

        self.bruteforce_var = tk.BooleanVar()
        self.bruteforce_checkbox = ttk.Checkbutton(self.option_frame, text="Enable Bruteforce(Might Take Long)",
                                                   variable=self.bruteforce_var)
        self.bruteforce_checkbox.pack(side=tk.LEFT, padx=5)

        self.progress_frame = tk.Frame(self.scan_frame, bg='#f0f0f0')
        self.progress_frame.pack()

        self.progress_label = ttk.Label(self.progress_frame, text="Progress:")
        self.progress_label.pack(side=tk.LEFT, padx=5)

        self.progress_bar = ttk.Progressbar(self.progress_frame, orient="horizontal", length=400, mode="determinate")
        self.progress_bar.pack(side=tk.LEFT, padx=5)

        self.progress_percentage = ttk.Label(self.progress_frame, text="0%")
        self.progress_percentage.pack(side=tk.LEFT, padx=5)

        self.status_label = ttk.Label(self.scan_frame, text="", background='#f0f0f0')
        self.status_label.pack(pady=10)

        self.subdomain_listbox = tk.Listbox(self.scan_frame, width=80, height=20, font=("Arial", 12))
        self.subdomain_listbox.pack(pady=10)
        self.subdomain_listbox.bind("<Double-Button-1>", self.controller.show_subdomain_details)

    def create_previous_scans_frame(self):
        self.previous_scans_listbox = tk.Listbox(self.previous_scans_frame, width=80, height=20, font=("Arial", 12))
        self.previous_scans_listbox.pack(pady=10)
        self.previous_scans_listbox.bind("<Double-Button-1>", self.controller.load_selected_scan)

        self.previous_scans_status_label = ttk.Label(self.previous_scans_frame, text="", background='#f0f0f0')
        self.previous_scans_status_label.pack(pady=10)

    def create_scheduled_scan_frame(self):
        self.schedule_domain_frame = tk.Frame(self.scheduled_scans_frame, pady=15, bg='#f0f0f0')
        self.schedule_domain_frame.grid(row=0, column=0, sticky='w')

        self.schedule_domain_label = ttk.Label(self.schedule_domain_frame, text="Enter domain name:")
        self.schedule_domain_label.grid(row=0, column=0, padx=5)

        self.schedule_domain_entry = ttk.Entry(self.schedule_domain_frame, width=50)
        self.schedule_domain_entry.grid(row=0, column=1, padx=5)

        self.schedule_button = ttk.Button(self.schedule_domain_frame, text="Schedule Scan",
                                          command=self.controller.schedule_scan)
        self.schedule_button.grid(row=0, column=2, padx=5)

        self.schedule_option_frame = tk.Frame(self.scheduled_scans_frame, pady=15, bg='#f0f0f0')
        self.schedule_option_frame.grid(row=1, column=0, sticky='w')

        self.schedule_port_label = ttk.Label(self.schedule_option_frame, text="Port range (default: 1-1024):")
        self.schedule_port_label.grid(row=0, column=0, padx=5)

        self.schedule_port_entry = ttk.Entry(self.schedule_option_frame, width=20)
        self.schedule_port_entry.grid(row=0, column=1, padx=5)

        self.schedule_bruteforce_var = tk.BooleanVar()
        self.schedule_bruteforce_checkbox = ttk.Checkbutton(self.schedule_option_frame,
                                                            text="Enable Bruteforce(Might Take Long)",
                                                            variable=self.schedule_bruteforce_var)
        self.schedule_bruteforce_checkbox.grid(row=0, column=2, padx=5)

        self.schedule_time_frame = tk.Frame(self.scheduled_scans_frame, pady=15, bg='#f0f0f0')
        self.schedule_time_frame.grid(row=2, column=0, sticky='w')

        # Start after x seconds frame
        self.start_after_x_seconds_frame = ttk.Frame(self.schedule_time_frame)
        self.start_after_x_seconds_frame.grid(row=0, column=0, sticky='w')

        self.entry1_disabled = True

        self.start_after_x_seconds_radiobutton = ttk.Radiobutton(self.start_after_x_seconds_frame,
                                                                 value="option1",
                                                                 command=self.controller.enable_entry1)
        self.start_after_x_seconds_radiobutton.grid(row=0, column=0, padx=5)

        self.start_after_x_seconds_label = ttk.Label(self.start_after_x_seconds_frame,
                                                     text="Schedule to x seconds later:")
        self.start_after_x_seconds_label.grid(row=0, column=1, padx=5)

        self.start_after_x_seconds_entry = ttk.Entry(self.start_after_x_seconds_frame, state="disabled")
        self.start_after_x_seconds_entry.grid(row=0, column=2, padx=5)

        # Exact date frame
        self.exact_date_frame = ttk.Frame(self.schedule_time_frame)
        self.exact_date_frame.grid(row=1, column=0, sticky='w')

        self.exact_date_radiobutton = ttk.Radiobutton(self.exact_date_frame,
                                                      value="option2",
                                                      command=self.controller.enable_entry2)
        self.exact_date_radiobutton.grid(row=0, column=0, padx=5)

        self.schedule_time_label = ttk.Label(self.exact_date_frame, text="Schedule time: (d/m/y h/m/s)")
        self.schedule_time_label.grid(row=0, column=1, padx=5)

        self.entry2_disabled = True

        self.day_entry = ttk.Entry(self.exact_date_frame, width=3, state="disabled")
        self.day_entry.grid(row=0, column=2, padx=2)
        self.day_entry.insert(0, datetime.now().strftime('%d'))

        self.month_entry = ttk.Entry(self.exact_date_frame, width=3, state="disabled")
        self.month_entry.grid(row=0, column=3, padx=2)
        self.month_entry.insert(0, datetime.now().strftime('%m'))

        self.year_entry = ttk.Entry(self.exact_date_frame, width=5, state="disabled")
        self.year_entry.grid(row=0, column=4, padx=2)
        self.year_entry.insert(0, datetime.now().strftime('%Y'))

        self.hour_entry = ttk.Entry(self.exact_date_frame, width=3, state="disabled")
        self.hour_entry.grid(row=0, column=5, padx=2)
        self.hour_entry.insert(0, datetime.now().strftime('%H'))

        self.minute_entry = ttk.Entry(self.exact_date_frame, width=3, state="disabled")
        self.minute_entry.grid(row=0, column=6, padx=2)
        self.minute_entry.insert(0, datetime.now().strftime('%M'))

        self.second_entry = ttk.Entry(self.exact_date_frame, width=3, state="disabled")
        self.second_entry.grid(row=0, column=7, padx=2)
        self.second_entry.insert(0, datetime.now().strftime('%S'))

        self.scheduled_status_label = ttk.Label(self.schedule_time_frame, text="", background='#f0f0f0')
        self.scheduled_status_label.grid(row=3, column=0, pady=10)

        self.schedule_listbox = tk.Listbox(self.schedule_time_frame, width=80, height=20, font=("Arial", 12))
        self.schedule_listbox.grid(row=4, column=0, pady=10)

    def get_schedule_time(self):
        day = self.day_entry.get()
        month = self.month_entry.get()
        year = self.year_entry.get()
        hour = self.hour_entry.get()
        minute = self.minute_entry.get()
        second = self.second_entry.get()
        return f"{day}-{month}-{year} {hour}:{minute}:{second}"
