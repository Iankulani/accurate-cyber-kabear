import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, Canvas, Frame
import threading
import socket
import subprocess
import time
import json
import os
import platform
import requests
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
import pandas as pd
from scapy.all import ARP, Ether, srp, conf
import netifaces
import ipaddress

class accuratecyberbear:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Bear")
        self.root.geometry("1200x800")
        self.root.configure(bg='#FFA500')  # Orange background
        
        # Initialize variables
        self.monitoring = False
        self.monitored_ips = set()
        self.monitored_ipv6s = set()
        self.telegram_chat_id = ""
        self.telegram_token = ""
        self.scan_results = {}
        self.monitoring_thread = None
        
        # Set orange theme
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#FFA500')
        self.style.configure('TLabel', background='#FFA500', foreground='black')
        self.style.configure('TButton', background='#FF8C00', foreground='black')
        self.style.configure('TEntry', fieldbackground='#FFD580')
        self.style.configure('TText', background='#FFD580')
        self.style.configure('TNotebook', background='#FFA500')
        self.style.configure('TNotebook.Tab', background='#FF8C00', foreground='black')
        
        # Create main menu
        self.create_menu()
        
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.monitoring_tab = ttk.Frame(self.notebook)
        self.scan_tab = ttk.Frame(self.notebook)
        self.visualization_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.dashboard_tab, text='Dashboard')
        self.notebook.add(self.monitoring_tab, text='Monitoring')
        self.notebook.add(self.scan_tab, text='Scanning')
        self.notebook.add(self.visualization_tab, text='Visualization')
        self.notebook.add(self.settings_tab, text='Settings')
        
        # Setup each tab
        self.setup_dashboard_tab()
        self.setup_monitoring_tab()
        self.setup_scan_tab()
        self.setup_visualization_tab()
        self.setup_settings_tab()
        
        # CLI interface
        self.setup_cli_interface()
        
        # Load configuration if exists
        self.load_config()
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dashboard", command=lambda: self.notebook.select(0))
        view_menu.add_command(label="Monitoring", command=lambda: self.notebook.select(1))
        view_menu.add_command(label="Scanning", command=lambda: self.notebook.select(2))
        view_menu.add_command(label="Visualization", command=lambda: self.notebook.select(3))
        view_menu.add_command(label="Settings", command=lambda: self.notebook.select(4))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Ping IP", command=self.ping_ip_dialog)
        tools_menu.add_command(label="Ping IPv6", command=self.ping_ipv6_dialog)
        tools_menu.add_command(label="Quick Scan", command=self.quick_scan_dialog)
        tools_menu.add_command(label="Deep Scan", command=self.deep_scan_dialog)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        self.root.config(menu=menubar)
    
    def setup_dashboard_tab(self):
        # Dashboard frame
        dashboard_frame = ttk.Frame(self.dashboard_tab)
        dashboard_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Status overview
        status_frame = ttk.LabelFrame(dashboard_frame, text="Status Overview")
        status_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(status_frame, text="Monitoring Status:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        self.monitoring_status_var = tk.StringVar(value="Stopped")
        ttk.Label(status_frame, textvariable=self.monitoring_status_var).grid(row=0, column=1, sticky='w', padx=5, pady=2)
        
        ttk.Label(status_frame, text="Monitored IPs:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        self.monitored_ips_var = tk.StringVar(value="0")
        ttk.Label(status_frame, textvariable=self.monitored_ips_var).grid(row=1, column=1, sticky='w', padx=5, pady=2)
        
        ttk.Label(status_frame, text="Monitored IPv6s:").grid(row=2, column=0, sticky='w', padx=5, pady=2)
        self.monitored_ipv6s_var = tk.StringVar(value="0")
        ttk.Label(status_frame, textvariable=self.monitored_ipv6s_var).grid(row=2, column=1, sticky='w', padx=5, pady=2)
        
        # Recent activities
        activity_frame = ttk.LabelFrame(dashboard_frame, text="Recent Activities")
        activity_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.activity_log = scrolledtext.ScrolledText(activity_frame, height=10)
        self.activity_log.pack(fill='both', expand=True, padx=5, pady=5)
        self.activity_log.config(state=tk.DISABLED)
        
        # Quick actions
        action_frame = ttk.LabelFrame(dashboard_frame, text="Quick Actions")
        action_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(action_frame, text="Start Monitoring", command=self.start_monitoring).pack(side='left', padx=5, pady=5)
        ttk.Button(action_frame, text="Stop Monitoring", command=self.stop_monitoring).pack(side='left', padx=5, pady=5)
        ttk.Button(action_frame, text="View Monitored", command=self.view_monitored).pack(side='left', padx=5, pady=5)
    
    def setup_monitoring_tab(self):
        # Monitoring frame
        monitoring_frame = ttk.Frame(self.monitoring_tab)
        monitoring_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Add IP section
        add_ip_frame = ttk.LabelFrame(monitoring_frame, text="Add IP to Monitor")
        add_ip_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(add_ip_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        self.ip_entry = ttk.Entry(add_ip_frame)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(add_ip_frame, text="Add IPv4", command=self.add_ip).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(add_ip_frame, text="Add IPv6", command=self.add_ipv6).grid(row=0, column=3, padx=5, pady=5)
        
        # Remove IP section
        remove_ip_frame = ttk.LabelFrame(monitoring_frame, text="Remove IP from Monitoring")
        remove_ip_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(remove_ip_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        self.remove_ip_entry = ttk.Entry(remove_ip_frame)
        self.remove_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(remove_ip_frame, text="Remove IPv4", command=self.remove_ip).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(remove_ip_frame, text="Remove IPv6", command=self.remove_ipv6).grid(row=0, column=3, padx=5, pady=5)
        
        # Monitored IPs list
        list_frame = ttk.LabelFrame(monitoring_frame, text="Monitored IP Addresses")
        list_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create treeview
        columns = ("IP Address", "Type", "Status", "Last Checked")
        self.monitored_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        
        for col in columns:
            self.monitored_tree.heading(col, text=col)
            self.monitored_tree.column(col, width=150)
        
        self.monitored_tree.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.monitored_tree.yview)
        self.monitored_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
    
    def setup_scan_tab(self):
        # Scan frame
        scan_frame = ttk.Frame(self.scan_tab)
        scan_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Scan options
        options_frame = ttk.LabelFrame(scan_frame, text="Scan Options")
        options_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(options_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5)
        self.scan_ip_entry = ttk.Entry(options_frame)
        self.scan_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Button(options_frame, text="Quick Scan", command=self.quick_scan).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(options_frame, text="Deep Scan", command=self.deep_scan).grid(row=0, column=3, padx=5, pady=5)
        ttk.Button(options_frame, text="IPv6 Scan", command=self.ipv6_scan).grid(row=0, column=4, padx=5, pady=5)
        
        # Scan results
        results_frame = ttk.LabelFrame(scan_frame, text="Scan Results")
        results_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.scan_results_text = scrolledtext.ScrolledText(results_frame, height=15)
        self.scan_results_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.scan_results_text.config(state=tk.DISABLED)
        
        # Progress bar
        self.scan_progress = ttk.Progressbar(scan_frame, mode='indeterminate')
        self.scan_progress.pack(fill='x', padx=5, pady=5)
    
    def setup_visualization_tab(self):
        # Visualization frame
        vis_frame = ttk.Frame(self.visualization_tab)
        vis_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(10, 8), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.fig, master=vis_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
        
        # Buttons to update charts
        button_frame = ttk.Frame(vis_frame)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(button_frame, text="Update Charts", command=self.update_charts).pack(side='left', padx=5, pady=5)
        ttk.Button(button_frame, text="Export Charts", command=self.export_charts).pack(side='left', padx=5, pady=5)
    
    def setup_settings_tab(self):
        # Settings frame
        settings_frame = ttk.Frame(self.settings_tab)
        settings_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Telegram configuration
        telegram_frame = ttk.LabelFrame(settings_frame, text="Telegram Configuration")
        telegram_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(telegram_frame, text="Bot Token:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.telegram_token_entry = ttk.Entry(telegram_frame, width=50)
        self.telegram_token_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        
        ttk.Label(telegram_frame, text="Chat ID:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.telegram_chat_id_entry = ttk.Entry(telegram_frame, width=50)
        self.telegram_chat_id_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
        ttk.Button(telegram_frame, text="Save Telegram Config", command=self.save_telegram_config).grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        ttk.Button(telegram_frame, text="Test Telegram", command=self.test_telegram).grid(row=3, column=0, columnspan=2, padx=5, pady=5)
        
        # Application settings
        app_frame = ttk.LabelFrame(settings_frame, text="Application Settings")
        app_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(app_frame, text="Update Interval (seconds):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.update_interval_var = tk.StringVar(value="60")
        ttk.Entry(app_frame, textvariable=self.update_interval_var, width=10).grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Button(app_frame, text="Save Settings", command=self.save_settings).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(app_frame, text="Load Settings", command=self.load_config).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(app_frame, text="Reset Settings", command=self.reset_settings).grid(row=1, column=2, padx=5, pady=5)
    
    def setup_cli_interface(self):
        # CLI frame at the bottom
        cli_frame = ttk.LabelFrame(self.root, text="Command Line Interface")
        cli_frame.pack(fill='x', padx=10, pady=10)
        
        self.cli_input = ttk.Entry(cli_frame)
        self.cli_input.pack(fill='x', padx=5, pady=5)
        self.cli_input.bind('<Return>', self.process_cli_command)
        
        self.cli_output = scrolledtext.ScrolledText(cli_frame, height=5)
        self.cli_output.pack(fill='x', padx=5, pady=5)
        self.cli_output.config(state=tk.DISABLED)
        
        ttk.Button(cli_frame, text="Clear CLI", command=self.clear_cli).pack(side='right', padx=5, pady=5)
        ttk.Button(cli_frame, text="Help", command=self.show_help).pack(side='right', padx=5, pady=5)
    
    def process_cli_command(self, event):
        command = self.cli_input.get().strip().lower()
        self.cli_input.delete(0, tk.END)
        
        self.add_to_cli_output(f"> {command}")
        
        if command == "help":
            self.show_help()
        elif command.startswith("ping ip "):
            ip = command[8:]
            self.ping_ip(ip)
        elif command.startswith("ping ipv6 "):
            ip = command[10:]
            self.ping_ipv6(ip)
        elif command.startswith("start monitoring "):
            ip = command[17:]
            self.add_ip_to_monitor(ip)
        elif command == "stop":
            self.stop_monitoring()
        elif command == "view":
            self.view_monitored()
        elif command == "monitor":
            self.start_monitoring()
        elif command == "exit":
            self.root.quit()
        elif command.startswith("add ip "):
            ip = command[7:]
            self.add_ip_to_monitor(ip)
        elif command.startswith("remove ip "):
            ip = command[10:]
            self.remove_ip_from_monitor(ip)
        elif command.startswith("remove ipv6 "):
            ip = command[12:]
            self.remove_ipv6_from_monitor(ip)
        elif command.startswith("config telegram chat_id "):
            chat_id = command[24:]
            self.telegram_chat_id = chat_id
            self.add_to_cli_output(f"Telegram Chat ID set to: {chat_id}")
        elif command.startswith("config telegram token "):
            token = command[22:]
            self.telegram_token = token
            self.add_to_cli_output(f"Telegram Token set to: {token}")
        elif command == "export data":
            self.export_data()
        elif command.startswith("add ipv6 "):
            ip = command[9:]
            self.add_ipv6_to_monitor(ip)
        elif command.startswith("ping ipv6 "):
            ip = command[10:]
            self.ping_ipv6(ip)
        elif command.startswith("r scan ip "):
            ip = command[10:]
            self.quick_scan(ip)
        elif command.startswith("scan ipv6 "):
            ip = command[10:]
            self.ipv6_scan(ip)
        elif command.startswith("deep scan ip "):
            ip = command[13:]
            self.deep_scan(ip)
        else:
            self.add_to_cli_output("Unknown command. Type 'help' for available commands.")
    
    def add_to_cli_output(self, text):
        self.cli_output.config(state=tk.NORMAL)
        self.cli_output.insert(tk.END, text + "\n")
        self.cli_output.see(tk.END)
        self.cli_output.config(state=tk.DISABLED)
    
    def clear_cli(self):
        self.cli_output.config(state=tk.NORMAL)
        self.cli_output.delete(1.0, tk.END)
        self.cli_output.config(state=tk.DISABLED)
    
    def show_help(self):
        help_text = """
Available commands:
- help: Show this help message
- ping ip <IP>: Ping an IPv4 address
- ping ipv6 <IP>: Ping an IPv6 address
- start monitoring <IP>: Start monitoring an IP address
- stop: Stop monitoring
- view: View monitored IPs
- monitor: Start monitoring all added IPs
- exit: Exit the application
- add ip <IP>: Add an IP to monitor
- remove ip <IP>: Remove an IP from monitoring
- remove ipv6 <IP>: Remove an IPv6 from monitoring
- config telegram chat_id <ID>: Set Telegram chat ID
- config telegram token <TOKEN>: Set Telegram bot token
- export data: Export data to Telegram
- add ipv6 <IP>: Add an IPv6 address to monitor
- r scan ip <IP>: Quick scan an IP
- scan ipv6 <IP>: Scan an IPv6 address
- deep scan ip <IP>: Deep scan an IP (all ports)
"""
        self.add_to_cli_output(help_text)
    
    def ping_ip(self, ip=None):
        if not ip:
            ip = self.ip_entry.get()
        
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "4", ip]
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.add_to_activity_log(f"Ping to {ip} successful")
                self.add_to_cli_output(f"Ping to {ip} successful")
            else:
                self.add_to_activity_log(f"Ping to {ip} failed")
                self.add_to_cli_output(f"Ping to {ip} failed")
                
        except Exception as e:
            self.add_to_activity_log(f"Error pinging {ip}: {str(e)}")
            self.add_to_cli_output(f"Error pinging {ip}: {str(e)}")
    
    def ping_ipv6(self, ip=None):
        if not ip:
            ip = self.ip_entry.get()
        
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping6", param, "4", ip]
            result = subprocess.run(command, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.add_to_activity_log(f"Ping to IPv6 {ip} successful")
                self.add_to_cli_output(f"Ping to IPv6 {ip} successful")
            else:
                self.add_to_activity_log(f"Ping to IPv6 {ip} failed")
                self.add_to_cli_output(f"Ping to IPv6 {ip} failed")
                
        except Exception as e:
            self.add_to_activity_log(f"Error pinging IPv6 {ip}: {str(e)}")
            self.add_to_cli_output(f"Error pinging IPv6 {ip}: {str(e)}")
    
    def add_ip(self):
        ip = self.ip_entry.get()
        if ip:
            self.add_ip_to_monitor(ip)
            self.ip_entry.delete(0, tk.END)
    
    def add_ipv6(self):
        ip = self.ip_entry.get()
        if ip:
            self.add_ipv6_to_monitor(ip)
            self.ip_entry.delete(0, tk.END)
    
    def remove_ip(self):
        ip = self.remove_ip_entry.get()
        if ip:
            self.remove_ip_from_monitor(ip)
            self.remove_ip_entry.delete(0, tk.END)
    
    def remove_ipv6(self):
        ip = self.remove_ip_entry.get()
        if ip:
            self.remove_ipv6_from_monitor(ip)
            self.remove_ip_entry.delete(0, tk.END)
    
    def add_ip_to_monitor(self, ip):
        try:
            # Validate IP address
            socket.inet_pton(socket.AF_INET, ip)
            self.monitored_ips.add(ip)
            self.update_monitored_display()
            self.add_to_activity_log(f"Added IPv4 {ip} to monitoring")
            self.add_to_cli_output(f"Added IPv4 {ip} to monitoring")
        except socket.error:
            messagebox.showerror("Error", "Invalid IPv4 address")
    
    def add_ipv6_to_monitor(self, ip):
        try:
            # Validate IPv6 address
            socket.inet_pton(socket.AF_INET6, ip)
            self.monitored_ipv6s.add(ip)
            self.update_monitored_display()
            self.add_to_activity_log(f"Added IPv6 {ip} to monitoring")
            self.add_to_cli_output(f"Added IPv6 {ip} to monitoring")
        except socket.error:
            messagebox.showerror("Error", "Invalid IPv6 address")
    
    def remove_ip_from_monitor(self, ip):
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            self.update_monitored_display()
            self.add_to_activity_log(f"Removed IPv4 {ip} from monitoring")
            self.add_to_cli_output(f"Removed IPv4 {ip} from monitoring")
        else:
            messagebox.showwarning("Warning", f"IPv4 {ip} not found in monitored list")
    
    def remove_ipv6_from_monitor(self, ip):
        if ip in self.monitored_ipv6s:
            self.monitored_ipv6s.remove(ip)
            self.update_monitored_display()
            self.add_to_activity_log(f"Removed IPv6 {ip} from monitoring")
            self.add_to_cli_output(f"Removed IPv6 {ip} from monitoring")
        else:
            messagebox.showwarning("Warning", f"IPv6 {ip} not found in monitored list")
    
    def update_monitored_display(self):
        # Clear the treeview
        for item in self.monitored_tree.get_children():
            self.monitored_tree.delete(item)
        
        # Add IPv4 addresses
        for ip in self.monitored_ips:
            self.monitored_tree.insert("", "end", values=(ip, "IPv4", "Pending", "-"))
        
        # Add IPv6 addresses
        for ip in self.monitored_ipv6s:
            self.monitored_tree.insert("", "end", values=(ip, "IPv6", "Pending", "-"))
        
        # Update counters
        self.monitored_ips_var.set(str(len(self.monitored_ips)))
        self.monitored_ipv6s_var.set(str(len(self.monitored_ipv6s)))
    
    def start_monitoring(self):
        if not self.monitored_ips and not self.monitored_ipv6s:
            messagebox.showwarning("Warning", "No IP addresses to monitor")
            return
        
        if self.monitoring:
            messagebox.showinfo("Info", "Monitoring is already running")
            return
        
        self.monitoring = True
        self.monitoring_status_var.set("Running")
        self.add_to_activity_log("Started monitoring")
        self.add_to_cli_output("Started monitoring")
        
        # Start monitoring in a separate thread
        self.monitoring_thread = threading.Thread(target=self.monitor_ips)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
    
    def stop_monitoring(self):
        if not self.monitoring:
            messagebox.showinfo("Info", "Monitoring is not running")
            return
        
        self.monitoring = False
        self.monitoring_status_var.set("Stopped")
        self.add_to_activity_log("Stopped monitoring")
        self.add_to_cli_output("Stopped monitoring")
    
    def monitor_ips(self):
        while self.monitoring:
            try:
                # Check all monitored IPs
                for ip in self.monitored_ips:
                    self.check_ip_status(ip, "IPv4")
                
                for ip in self.monitored_ipv6s:
                    self.check_ip_status(ip, "IPv6")
                
                # Wait for the specified interval
                interval = int(self.update_interval_var.get())
                time.sleep(interval)
                
            except Exception as e:
                self.add_to_activity_log(f"Error in monitoring: {str(e)}")
                time.sleep(60)  # Wait a minute before retrying
    
    def check_ip_status(self, ip, ip_type):
        try:
            if ip_type == "IPv4":
                param = "-n" if platform.system().lower() == "windows" else "-c"
                command = ["ping", param, "1", ip]
            else:
                param = "-n" if platform.system().lower() == "windows" else "-c"
                command = ["ping6", param, "1", ip]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            status = "Online" if result.returncode == 0 else "Offline"
            
            # Update the treeview
            for item in self.monitored_tree.get_children():
                if self.monitored_tree.item(item, "values")[0] == ip:
                    self.monitored_tree.set(item, "Status", status)
                    self.monitored_tree.set(item, "Last Checked", datetime.now().strftime("%H:%M:%S"))
                    break
            
            # Log status changes
            if status == "Offline":
                self.add_to_activity_log(f"{ip_type} {ip} is offline")
                self.send_telegram_alert(f"{ip_type} {ip} is offline")
                
        except subprocess.TimeoutExpired:
            for item in self.monitored_tree.get_children():
                if self.monitored_tree.item(item, "values")[0] == ip:
                    self.monitored_tree.set(item, "Status", "Timeout")
                    self.monitored_tree.set(item, "Last Checked", datetime.now().strftime("%H:%M:%S"))
                    break
            
            self.add_to_activity_log(f"{ip_type} {ip} timeout")
            self.send_telegram_alert(f"{ip_type} {ip} timeout")
        
        except Exception as e:
            self.add_to_activity_log(f"Error checking {ip_type} {ip}: {str(e)}")
    
    def view_monitored(self):
        if not self.monitored_ips and not self.monitored_ipv6s:
            self.add_to_cli_output("No IP addresses being monitored")
            return
        
        self.add_to_cli_output("Monitored IPv4 addresses:")
        for ip in self.monitored_ips:
            self.add_to_cli_output(f"  {ip}")
        
        self.add_to_cli_output("Monitored IPv6 addresses:")
        for ip in self.monitored_ipv6s:
            self.add_to_cli_output(f"  {ip}")
    
    def quick_scan(self, ip=None):
        if not ip:
            ip = self.scan_ip_entry.get()
        
        if not ip:
            messagebox.showwarning("Warning", "Please enter an IP address to scan")
            return
        
        try:
            self.scan_progress.start()
            self.add_to_activity_log(f"Starting quick scan of {ip}")
            
            # Run nmap scan in a separate thread
            threading.Thread(target=self.run_quick_scan, args=(ip,), daemon=True).start()
            
        except Exception as e:
            self.add_to_activity_log(f"Error starting quick scan: {str(e)}")
            self.scan_progress.stop()
    
    def run_quick_scan(self, ip):
        try:
            command = ["nmap", "-F", ip]
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            
            self.scan_results_text.config(state=tk.NORMAL)
            self.scan_results_text.delete(1.0, tk.END)
            self.scan_results_text.insert(tk.END, result.stdout)
            
            if result.stderr:
                self.scan_results_text.insert(tk.END, f"\nErrors:\n{result.stderr}")
            
            self.scan_results_text.config(state=tk.DISABLED)
            self.add_to_activity_log(f"Quick scan of {ip} completed")
            
            # Save results
            self.scan_results[ip] = {
                "type": "quick",
                "timestamp": datetime.now().isoformat(),
                "results": result.stdout
            }
            
        except subprocess.TimeoutExpired:
            self.scan_results_text.config(state=tk.NORMAL)
            self.scan_results_text.delete(1.0, tk.END)
            self.scan_results_text.insert(tk.END, f"Scan of {ip} timed out")
            self.scan_results_text.config(state=tk.DISABLED)
            self.add_to_activity_log(f"Quick scan of {ip} timed out")
        
        except Exception as e:
            self.scan_results_text.config(state=tk.NORMAL)
            self.scan_results_text.delete(1.0, tk.END)
            self.scan_results_text.insert(tk.END, f"Error scanning {ip}: {str(e)}")
            self.scan_results_text.config(state=tk.DISABLED)
            self.add_to_activity_log(f"Error during quick scan of {ip}: {str(e)}")
        
        finally:
            self.scan_progress.stop()
    
    def deep_scan(self, ip=None):
        if not ip:
            ip = self.scan_ip_entry.get()
        
        if not ip:
            messagebox.showwarning("Warning", "Please enter an IP address to scan")
            return
        
        try:
            self.scan_progress.start()
            self.add_to_activity_log(f"Starting deep scan of {ip}")
            
            # Run nmap scan in a separate thread
            threading.Thread(target=self.run_deep_scan, args=(ip,), daemon=True).start()
            
        except Exception as e:
            self.add_to_activity_log(f"Error starting deep scan: {str(e)}")
            self.scan_progress.stop()
    
    def run_deep_scan(self, ip):
        try:
            command = ["nmap", "-p", "1-65535", "-sV", "-sC", "-A", "-O", ip]
            result = subprocess.run(command, capture_output=True, text=True, timeout=3600)
            
            self.scan_results_text.config(state=tk.NORMAL)
            self.scan_results_text.delete(1.0, tk.END)
            self.scan_results_text.insert(tk.END, result.stdout)
            
            if result.stderr:
                self.scan_results_text.insert(tk.END, f"\nErrors:\n{result.stderr}")
            
            self.scan_results_text.config(state=tk.DISABLED)
            self.add_to_activity_log(f"Deep scan of {ip} completed")
            
            # Save results
            self.scan_results[ip] = {
                "type": "deep",
                "timestamp": datetime.now().isoformat(),
                "results": result.stdout
            }
            
        except subprocess.TimeoutExpired:
            self.scan_results_text.config(state=tk.NORMAL)
            self.scan_results_text.delete(1.0, tk.END)
            self.scan_results_text.insert(tk.END, f"Scan of {ip} timed out")
            self.scan_results_text.config(state=tk.DISABLED)
            self.add_to_activity_log(f"Deep scan of {ip} timed out")
        
        except Exception as e:
            self.scan_results_text.config(state=tk.NORMAL)
            self.scan_results_text.delete(1.0, tk.END)
            self.scan_results_text.insert(tk.END, f"Error scanning {ip}: {str(e)}")
            self.scan_results_text.config(state=tk.DISABLED)
            self.add_to_activity_log(f"Error during deep scan of {ip}: {str(e)}")
        
        finally:
            self.scan_progress.stop()
    
    def ipv6_scan(self, ip=None):
        if not ip:
            ip = self.scan_ip_entry.get()
        
        if not ip:
            messagebox.showwarning("Warning", "Please enter an IPv6 address to scan")
            return
        
        try:
            self.scan_progress.start()
            self.add_to_activity_log(f"Starting IPv6 scan of {ip}")
            
            # Run nmap scan in a separate thread
            threading.Thread(target=self.run_ipv6_scan, args=(ip,), daemon=True).start()
            
        except Exception as e:
            self.add_to_activity_log(f"Error starting IPv6 scan: {str(e)}")
            self.scan_progress.stop()
    
    def run_ipv6_scan(self, ip):
        try:
            command = ["nmap", "-6", "-F", ip]
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            
            self.scan_results_text.config(state=tk.NORMAL)
            self.scan_results_text.delete(1.0, tk.END)
            self.scan_results_text.insert(tk.END, result.stdout)
            
            if result.stderr:
                self.scan_results_text.insert(tk.END, f"\nErrors:\n{result.stderr}")
            
            self.scan_results_text.config(state=tk.DISABLED)
            self.add_to_activity_log(f"IPv6 scan of {ip} completed")
            
            # Save results
            self.scan_results[ip] = {
                "type": "ipv6",
                "timestamp": datetime.now().isoformat(),
                "results": result.stdout
            }
            
        except subprocess.TimeoutExpired:
            self.scan_results_text.config(state=tk.NORMAL)
            self.scan_results_text.delete(1.0, tk.END)
            self.scan_results_text.insert(tk.END, f"Scan of {ip} timed out")
            self.scan_results_text.config(state=tk.DISABLED)
            self.add_to_activity_log(f"IPv6 scan of {ip} timed out")
        
        except Exception as e:
            self.scan_results_text.config(state=tk.NORMAL)
            self.scan_results_text.delete(1.0, tk.END)
            self.scan_results_text.insert(tk.END, f"Error scanning {ip}: {str(e)}")
            self.scan_results_text.config(state=tk.DISABLED)
            self.add_to_activity_log(f"Error during IPv6 scan of {ip}: {str(e)}")
        
        finally:
            self.scan_progress.stop()
    
    def update_charts(self):
        try:
            self.fig.clear()
            
            # Create some sample data for visualization
            ip_types = ['IPv4', 'IPv6']
            counts = [len(self.monitored_ips), len(self.monitored_ipv6s)]
            
            # Create bar chart
            ax1 = self.fig.add_subplot(121)
            ax1.bar(ip_types, counts, color=['#FF8C00', '#FFA500'])
            ax1.set_title('Monitored IP Addresses')
            ax1.set_ylabel('Count')
            
            # Create pie chart
            ax2 = self.fig.add_subplot(122)
            if sum(counts) > 0:
                ax2.pie(counts, labels=ip_types, autopct='%1.1f%%', colors=['#FF8C00', '#FFA500'])
            ax2.set_title('IP Address Distribution')
            
            self.fig.tight_layout()
            self.canvas.draw()
            
            self.add_to_activity_log("Charts updated")
            
        except Exception as e:
            self.add_to_activity_log(f"Error updating charts: {str(e)}")
    
    def export_charts(self):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cyber_security_charts_{timestamp}.png"
            self.fig.savefig(filename)
            self.add_to_activity_log(f"Charts exported to {filename}")
            messagebox.showinfo("Success", f"Charts exported to {filename}")
        except Exception as e:
            self.add_to_activity_log(f"Error exporting charts: {str(e)}")
            messagebox.showerror("Error", f"Failed to export charts: {str(e)}")
    
    def save_telegram_config(self):
        self.telegram_token = self.telegram_token_entry.get()
        self.telegram_chat_id = self.telegram_chat_id_entry.get()
        
        self.save_config()
        self.add_to_activity_log("Telegram configuration saved")
        messagebox.showinfo("Success", "Telegram configuration saved")
    
    def test_telegram(self):
        if not self.telegram_token or not self.telegram_chat_id:
            messagebox.showwarning("Warning", "Please configure Telegram token and chat ID first")
            return
        
        try:
            message = "Test message from Accurate Cyber Bear"
            self.send_telegram_message(message)
            self.add_to_activity_log("Test Telegram message sent")
            messagebox.showinfo("Success", "Test Telegram message sent")
        except Exception as e:
            self.add_to_activity_log(f"Error sending Telegram test: {str(e)}")
            messagebox.showerror("Error", f"Failed to send test message: {str(e)}")
    
    def send_telegram_message(self, message):
        if not self.telegram_token or not self.telegram_chat_id:
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                "chat_id": self.telegram_chat_id,
                "text": message
            }
            response = requests.post(url, data=data)
            return response.status_code == 200
        except Exception:
            return False
    
    def send_telegram_alert(self, message):
        if self.telegram_token and self.telegram_chat_id:
            self.send_telegram_message(f"ALERT: {message}")
    
    def export_data(self):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cyber_security_data_{timestamp}.json"
            
            data = {
                "monitored_ips": list(self.monitored_ips),
                "monitored_ipv6s": list(self.monitored_ipv6s),
                "scan_results": self.scan_results,
                "export_time": timestamp
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.add_to_activity_log(f"Data exported to {filename}")
            
            # Also send to Telegram if configured
            if self.telegram_token and self.telegram_chat_id:
                message = f"Cyber Security Data Export\nTimestamp: {timestamp}\nMonitored IPv4: {len(self.monitored_ips)}\nMonitored IPv6: {len(self.monitored_ipv6s)}"
                self.send_telegram_message(message)
            
            messagebox.showinfo("Success", f"Data exported to {filename}")
            
        except Exception as e:
            self.add_to_activity_log(f"Error exporting data: {str(e)}")
            messagebox.showerror("Error", f"Failed to export data: {str(e)}")
    
    def save_settings(self):
        self.save_config()
        self.add_to_activity_log("Settings saved")
        messagebox.showinfo("Success", "Settings saved")
    
    def reset_settings(self):
        result = messagebox.askyesno("Confirm", "Are you sure you want to reset all settings?")
        if result:
            self.monitored_ips = set()
            self.monitored_ipv6s = set()
            self.telegram_token = ""
            self.telegram_chat_id = ""
            self.scan_results = {}
            
            self.telegram_token_entry.delete(0, tk.END)
            self.telegram_chat_id_entry.delete(0, tk.END)
            self.update_interval_var.set("60")
            
            self.update_monitored_display()
            self.save_config()
            
            self.add_to_activity_log("Settings reset to defaults")
            messagebox.showinfo("Success", "Settings reset to defaults")
    
    def save_config(self):
        config = {
            "monitored_ips": list(self.monitored_ips),
            "monitored_ipv6s": list(self.monitored_ipv6s),
            "telegram_token": self.telegram_token,
            "telegram_chat_id": self.telegram_chat_id,
            "update_interval": self.update_interval_var.get()
        }
        
        try:
            with open("cyber_security_config.json", "w") as f:
                json.dump(config, f)
        except Exception as e:
            self.add_to_activity_log(f"Error saving config: {str(e)}")
    
    def load_config(self):
        try:
            if os.path.exists("cyber_security_config.json"):
                with open("cyber_security_config.json", "r") as f:
                    config = json.load(f)
                
                self.monitored_ips = set(config.get("monitored_ips", []))
                self.monitored_ipv6s = set(config.get("monitored_ipv6s", []))
                self.telegram_token = config.get("telegram_token", "")
                self.telegram_chat_id = config.get("telegram_chat_id", "")
                
                self.telegram_token_entry.delete(0, tk.END)
                self.telegram_token_entry.insert(0, self.telegram_token)
                
                self.telegram_chat_id_entry.delete(0, tk.END)
                self.telegram_chat_id_entry.insert(0, self.telegram_chat_id)
                
                self.update_interval_var.set(config.get("update_interval", "60"))
                
                self.update_monitored_display()
                self.add_to_activity_log("Configuration loaded")
                
        except Exception as e:
            self.add_to_activity_log(f"Error loading config: {str(e)}")
    
    def add_to_activity_log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        self.activity_log.config(state=tk.NORMAL)
        self.activity_log.insert(tk.END, log_message)
        self.activity_log.see(tk.END)
        self.activity_log.config(state=tk.DISABLED)
    
    def ping_ip_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Ping IP")
        dialog.geometry("300x100")
        dialog.configure(bg='#FFA500')
        
        ttk.Label(dialog, text="IP Address:").pack(pady=5)
        ip_entry = ttk.Entry(dialog)
        ip_entry.pack(pady=5)
        
        def do_ping():
            ip = ip_entry.get()
            if ip:
                self.ping_ip(ip)
                dialog.destroy()
        
        ttk.Button(dialog, text="Ping", command=do_ping).pack(pady=5)
    
    def ping_ipv6_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Ping IPv6")
        dialog.geometry("300x100")
        dialog.configure(bg='#FFA500')
        
        ttk.Label(dialog, text="IPv6 Address:").pack(pady=5)
        ip_entry = ttk.Entry(dialog)
        ip_entry.pack(pady=5)
        
        def do_ping():
            ip = ip_entry.get()
            if ip:
                self.ping_ipv6(ip)
                dialog.destroy()
        
        ttk.Button(dialog, text="Ping", command=do_ping).pack(pady=5)
    
    def quick_scan_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Quick Scan")
        dialog.geometry("300x100")
        dialog.configure(bg='#FFA500')
        
        ttk.Label(dialog, text="IP Address:").pack(pady=5)
        ip_entry = ttk.Entry(dialog)
        ip_entry.pack(pady=5)
        
        def do_scan():
            ip = ip_entry.get()
            if ip:
                self.quick_scan(ip)
                dialog.destroy()
        
        ttk.Button(dialog, text="Scan", command=do_scan).pack(pady=5)
    
    def deep_scan_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Deep Scan")
        dialog.geometry("300x100")
        dialog.configure(bg='#FFA500')
        
        ttk.Label(dialog, text="IP Address:").pack(pady=5)
        ip_entry = ttk.Entry(dialog)
        ip_entry.pack(pady=5)
        
        def do_scan():
            ip = ip_entry.get()
            if ip:
                self.deep_scan(ip)
                dialog.destroy()
        
        ttk.Button(dialog, text="Scan", command=do_scan).pack(pady=5)

def main():
    root = tk.Tk()
    app = accuratecyberbear(root)
    root.mainloop()

if __name__ == "__main__":
    main()