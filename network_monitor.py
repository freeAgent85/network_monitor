#!/usr/bin/env python3
"""
Network Interface Ping Monitor for Raspberry Pi OS

This application monitors network connectivity by pinging gateway addresses
and alerts users when consecutive ping failures occur.

Author: Vibes
Date: August 10, 2025
License: You are free to download, run, modify, and distribute this software in any way you'd like. The author provides no warranty or assurances as to its quality. Use of this software is at your own risk.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import time
import socket
import netifaces
from datetime import datetime
import queue
import sys
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl

class NetworkMonitor:
    """Main application class for network monitoring"""

    def __init__(self):
        """Initialize the network monitor application"""
        self.root = tk.Tk()
        self.root.title("Network Interface Ping Monitor")
        self.root.geometry("600x700")  # Increased size for additional options

        # Application state variables
        self.monitoring = False
        self.monitor_thread = None
        self.consecutive_failures = 0
        self.alert_queue = queue.Queue()
        self.restart_timer = None

        # Configuration variables
        self.selected_interface = tk.StringVar()
        self.target_ip = tk.StringVar()
        self.ping_frequency = tk.IntVar(value=10)
        self.failure_threshold = tk.IntVar(value=3)

        # Alert configuration variables
        self.alert_popup = tk.BooleanVar(value=True)
        self.alert_email = tk.BooleanVar(value=False)
        self.auto_restart = tk.BooleanVar(value=False)
        self.restart_delay = tk.IntVar(value=5)  # minutes

        # Email configuration variables
        self.smtp_server = tk.StringVar(value="smtp.gmail.com")
        self.smtp_port = tk.IntVar(value=587)
        self.smtp_use_tls = tk.BooleanVar(value=True)
        self.smtp_username = tk.StringVar()
        self.smtp_password = tk.StringVar()
        self.email_from = tk.StringVar()
        self.email_to = tk.StringVar()
        self.smtp_interface = tk.StringVar()

        # Initialize GUI components
        self.setup_gui()
        self.populate_interfaces()

        # Start checking for alerts
        self.check_alerts()

    def get_interface_gateway(self, interface):
        """
        Get gateway IP for a specific interface using route command
        Args:
            interface (str): Network interface name
        Returns:
            str: Gateway IP address or None if not found
        """
        try:
            # Use ip route command to get gateway for specific interface
            result = subprocess.run(['ip', 'route', 'show', 'dev', interface], 
                                  capture_output=True, text=True)

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    # Look for default route
                    if 'default' in line:
                        parts = line.split()
                        if 'via' in parts:
                            via_index = parts.index('via')
                            if via_index + 1 < len(parts):
                                return parts[via_index + 1]

                    # Look for network route that could indicate gateway
                    if 'via' in line and not line.startswith('169.254'):
                        parts = line.split()
                        via_index = parts.index('via')
                        if via_index + 1 < len(parts):
                            return parts[via_index + 1]

            # Fallback: try to get default gateway from netifaces
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                default_gateway = gateways['default'][netifaces.AF_INET]
                if len(default_gateway) > 1 and default_gateway[1] == interface:
                    return default_gateway[0]
                # If no specific interface match, return default gateway for any interface
                elif len(default_gateway) > 0:
                    return default_gateway[0]

        except Exception as e:
            print(f"Error getting gateway for {interface}: {e}")

        return None

    def get_interface_network(self, interface):
        """
        Get the network address for an interface to use as ping target
        Args:
            interface (str): Network interface name
        Returns:
            str: Network gateway or broadcast address
        """
        try:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                inet_info = addrs[netifaces.AF_INET][0]
                if 'addr' in inet_info and 'netmask' in inet_info:
                    ip = inet_info['addr']
                    netmask = inet_info['netmask']

                    # Calculate network address and potential gateway
                    ip_parts = [int(x) for x in ip.split('.')]
                    mask_parts = [int(x) for x in netmask.split('.')]

                    # Calculate network address
                    network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]

                    # Common gateway is usually network + 1
                    gateway_parts = network_parts[:]
                    gateway_parts[3] += 1

                    return '.'.join(map(str, gateway_parts))
        except Exception as e:
            print(f"Error calculating network for {interface}: {e}")

        return None

    def get_all_interfaces(self):
        """
        Get all network interfaces with their status and potential ping targets
        Returns: Dictionary with interface info
        """
        interfaces = {}

        try:
            # Get all network interfaces
            for interface in netifaces.interfaces():
                # Skip loopback interface
                if interface == 'lo':
                    continue

                interface_info = {
                    'name': interface,
                    'status': 'down',
                    'ip': None,
                    'gateway': None,
                    'suggested_target': None
                }

                # Check if interface has an IP address
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    inet_info = addrs[netifaces.AF_INET][0]
                    if 'addr' in inet_info:
                        interface_info['ip'] = inet_info['addr']
                        interface_info['status'] = 'up'

                        # Try to get gateway for this interface
                        gateway = self.get_interface_gateway(interface)
                        if gateway:
                            interface_info['gateway'] = gateway
                            interface_info['suggested_target'] = gateway
                        else:
                            # If no gateway found, try to calculate network gateway
                            network_gateway = self.get_interface_network(interface)
                            if network_gateway:
                                interface_info['suggested_target'] = network_gateway
                            else:
                                # Last resort: use Google DNS as target
                                interface_info['suggested_target'] = '8.8.8.8'

                # Add interface even if it's down (user might want to monitor it)
                if interface_info['status'] == 'up' or self.interface_exists_in_system(interface):
                    interfaces[interface] = interface_info

        except Exception as e:
            print(f"Error detecting interfaces: {e}")

        return interfaces

    def interface_exists_in_system(self, interface):
        """
        Check if interface exists in system even if it's down
        Args:
            interface (str): Interface name
        Returns:
            bool: True if interface exists
        """
        try:
            result = subprocess.run(['ip', 'link', 'show', interface], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def get_primary_interface(self):
        """
        Determine the primary network interface (usually the one with default route)
        Returns:
            str: Primary interface name or None
        """
        try:
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                default_gateway = gateways['default'][netifaces.AF_INET]
                if len(default_gateway) > 1:
                    return default_gateway[1]  # Interface name
        except:
            pass

        # Fallback: return first active interface
        interfaces = self.get_all_interfaces()
        for name, info in interfaces.items():
            if info['status'] == 'up':
                return name

        return None

    def setup_gui(self):
        """Create and configure the main GUI interface"""
        # Create notebook for tabbed interface
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Main monitoring tab
        main_tab = ttk.Frame(notebook)
        notebook.add(main_tab, text="Monitoring")
        self.setup_main_tab(main_tab)

        # Alert configuration tab
        alert_tab = ttk.Frame(notebook)
        notebook.add(alert_tab, text="Alert Settings")
        self.setup_alert_tab(alert_tab)

        # Email configuration tab
        email_tab = ttk.Frame(notebook)
        notebook.add(email_tab, text="Email Settings")
        self.setup_email_tab(email_tab)

    def setup_main_tab(self, parent):
        """Setup the main monitoring tab"""
        main_frame = ttk.Frame(parent, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Interface selection with refresh button
        interface_frame = ttk.Frame(main_frame)
        interface_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        ttk.Label(interface_frame, text="Network Interface:").pack(side=tk.LEFT)
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.selected_interface, 
                                          state="readonly", width=25)
        self.interface_combo.pack(side=tk.LEFT, padx=(10, 5), fill=tk.X, expand=True)
        self.interface_combo.bind('<<ComboboxSelected>>', self.on_interface_change)

        refresh_button = ttk.Button(interface_frame, text="Refresh", 
                                  command=self.populate_interfaces, width=8)
        refresh_button.pack(side=tk.RIGHT)

        # Interface status display
        self.interface_status = ttk.Label(main_frame, text="", foreground="gray")
        self.interface_status.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(0, 5))

        # Target IP address
        ttk.Label(main_frame, text="Target IP Address:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.ip_entry = ttk.Entry(main_frame, textvariable=self.target_ip, width=30)
        self.ip_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5)

        # Ping frequency
        ttk.Label(main_frame, text="Ping Frequency (seconds):").grid(row=3, column=0, sticky=tk.W, pady=5)
        frequency_frame = ttk.Frame(main_frame)
        frequency_frame.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5)

        self.frequency_scale = ttk.Scale(frequency_frame, from_=1, to=60, 
                                       variable=self.ping_frequency, orient=tk.HORIZONTAL)
        self.frequency_scale.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.frequency_label = ttk.Label(frequency_frame, text="10")
        self.frequency_label.pack(side=tk.RIGHT, padx=(5, 0))

        self.frequency_scale.configure(command=self.update_frequency_label)

        # Failure threshold
        ttk.Label(main_frame, text="Failure Threshold:").grid(row=4, column=0, sticky=tk.W, pady=5)
        threshold_frame = ttk.Frame(main_frame)
        threshold_frame.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5)

        self.threshold_scale = ttk.Scale(threshold_frame, from_=1, to=10, 
                                       variable=self.failure_threshold, orient=tk.HORIZONTAL)
        self.threshold_scale.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.threshold_label = ttk.Label(threshold_frame, text="3")
        self.threshold_label.pack(side=tk.RIGHT, padx=(5, 0))

        self.threshold_scale.configure(command=self.update_threshold_label)

        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)

        self.start_button = ttk.Button(button_frame, text="Start Monitoring", 
                                     command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop Monitoring", 
                                    command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Test email button
        self.test_email_button = ttk.Button(button_frame, text="Test Email", 
                                          command=self.test_email_settings)
        self.test_email_button.pack(side=tk.LEFT, padx=5)

        # Status display
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        status_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)

        self.status_text = tk.Text(status_frame, height=10, width=50, state=tk.DISABLED)
        scrollbar = ttk.Scrollbar(status_frame, orient=tk.VERTICAL, command=self.status_text.yview)
        self.status_text.configure(yscrollcommand=scrollbar.set)

        self.status_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Configure grid weights for resizing
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(6, weight=1)

    def setup_alert_tab(self, parent):
        """Setup the alert configuration tab"""
        alert_frame = ttk.Frame(parent, padding="10")
        alert_frame.pack(fill=tk.BOTH, expand=True)

        # Alert method selection
        method_frame = ttk.LabelFrame(alert_frame, text="Alert Methods", padding="10")
        method_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Checkbutton(method_frame, text="Show popup window", 
                       variable=self.alert_popup).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(method_frame, text="Send email notification", 
                       variable=self.alert_email).pack(anchor=tk.W, pady=2)

        # Auto-restart configuration
        restart_frame = ttk.LabelFrame(alert_frame, text="Auto-Restart Settings", padding="10")
        restart_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Checkbutton(restart_frame, text="Automatically restart monitoring after alert", 
                       variable=self.auto_restart).pack(anchor=tk.W, pady=2)

        delay_frame = ttk.Frame(restart_frame)
        delay_frame.pack(fill=tk.X, pady=(5, 0))

        ttk.Label(delay_frame, text="Restart delay:").pack(side=tk.LEFT)
        delay_combo = ttk.Combobox(delay_frame, textvariable=self.restart_delay, 
                                  values=[1, 5, 10, 15, 30, 60], state="readonly", width=10)
        delay_combo.pack(side=tk.LEFT, padx=(10, 5))
        delay_combo.set(5)
        ttk.Label(delay_frame, text="minutes").pack(side=tk.LEFT)

    def setup_email_tab(self, parent):
        """Setup the email configuration tab"""
        email_frame = ttk.Frame(parent, padding="10")
        email_frame.pack(fill=tk.BOTH, expand=True)

        # SMTP server settings
        smtp_frame = ttk.LabelFrame(email_frame, text="SMTP Server Settings", padding="10")
        smtp_frame.pack(fill=tk.X, pady=(0, 10))

        # Server and port
        server_frame = ttk.Frame(smtp_frame)
        server_frame.pack(fill=tk.X, pady=2)
        ttk.Label(server_frame, text="SMTP Server:", width=15).pack(side=tk.LEFT)
        ttk.Entry(server_frame, textvariable=self.smtp_server, width=30).pack(side=tk.LEFT, padx=(5, 10))
        ttk.Label(server_frame, text="Port:", width=5).pack(side=tk.LEFT)
        ttk.Entry(server_frame, textvariable=self.smtp_port, width=8).pack(side=tk.LEFT, padx=(5, 0))

        # TLS option
        ttk.Checkbutton(smtp_frame, text="Use TLS encryption", 
                       variable=self.smtp_use_tls).pack(anchor=tk.W, pady=2)

        # Network interface for SMTP
        smtp_interface_frame = ttk.Frame(smtp_frame)
        smtp_interface_frame.pack(fill=tk.X, pady=2)
        ttk.Label(smtp_interface_frame, text="Network Interface:", width=15).pack(side=tk.LEFT)
        self.smtp_interface_combo = ttk.Combobox(smtp_interface_frame, textvariable=self.smtp_interface, 
                                               state="readonly", width=25)
        self.smtp_interface_combo.pack(side=tk.LEFT, padx=(5, 0))

        # Authentication settings
        auth_frame = ttk.LabelFrame(email_frame, text="Authentication", padding="10")
        auth_frame.pack(fill=tk.X, pady=(0, 10))

        # Username
        user_frame = ttk.Frame(auth_frame)
        user_frame.pack(fill=tk.X, pady=2)
        ttk.Label(user_frame, text="Username:", width=15).pack(side=tk.LEFT)
        ttk.Entry(user_frame, textvariable=self.smtp_username, width=40).pack(side=tk.LEFT, padx=(5, 0))

        # Password
        pass_frame = ttk.Frame(auth_frame)
        pass_frame.pack(fill=tk.X, pady=2)
        ttk.Label(pass_frame, text="Password:", width=15).pack(side=tk.LEFT)
        ttk.Entry(pass_frame, textvariable=self.smtp_password, width=40, show="*").pack(side=tk.LEFT, padx=(5, 0))

        # Email addresses
        email_addr_frame = ttk.LabelFrame(email_frame, text="Email Addresses", padding="10")
        email_addr_frame.pack(fill=tk.X, pady=(0, 10))

        # From address
        from_frame = ttk.Frame(email_addr_frame)
        from_frame.pack(fill=tk.X, pady=2)
        ttk.Label(from_frame, text="From:", width=15).pack(side=tk.LEFT)
        ttk.Entry(from_frame, textvariable=self.email_from, width=40).pack(side=tk.LEFT, padx=(5, 0))

        # To address
        to_frame = ttk.Frame(email_addr_frame)
        to_frame.pack(fill=tk.X, pady=2)
        ttk.Label(to_frame, text="To:", width=15).pack(side=tk.LEFT)
        ttk.Entry(to_frame, textvariable=self.email_to, width=40).pack(side=tk.LEFT, padx=(5, 0))

    def populate_interfaces(self):
        """Populate the interface dropdown with all available network interfaces"""
        interfaces = self.get_all_interfaces()
        self.interfaces_dict = interfaces

        # Create display names with status
        interface_display = []
        for name, info in interfaces.items():
            status_indicator = "🟢" if info['status'] == 'up' else "🔴"
            ip_info = f" ({info['ip']})" if info['ip'] else " (no IP)"
            display_name = f"{status_indicator} {name}{ip_info}"
            interface_display.append((display_name, name))

        # Sort by status (up first) then by name
        interface_display.sort(key=lambda x: (interfaces[x[1]]['status'] != 'up', x[1]))

        # Set combobox values
        display_names = [item[0] for item in interface_display]
        self.interface_combo['values'] = display_names

        # Also populate SMTP interface combo
        interface_names = [item[1] for item in interface_display]
        self.smtp_interface_combo['values'] = interface_names

        # Create mapping from display name to interface name
        self.display_to_interface = {item[0]: item[1] for item in interface_display}
        self.interface_to_display = {item[1]: item[0] for item in interface_display}

        if interface_display:
            # Try to select primary interface first
            primary = self.get_primary_interface()
            if primary and primary in self.interface_to_display:
                self.interface_combo.set(self.interface_to_display[primary])
                self.selected_interface.set(primary)
                self.smtp_interface.set(primary)  # Default SMTP interface to primary
            else:
                # Select first interface
                first_display = interface_display[0][0]
                first_interface = interface_display[0][1]
                self.interface_combo.set(first_display)
                self.selected_interface.set(first_interface)
                self.smtp_interface.set(first_interface)

            self.on_interface_change(None)

        self.log_status(f"Found {len(interfaces)} network interfaces")

    def on_interface_change(self, event):
        """Handle interface selection change"""
        # Get actual interface name from display name
        display_name = self.interface_combo.get()
        if display_name in self.display_to_interface:
            interface = self.display_to_interface[display_name]
            self.selected_interface.set(interface)

            if interface in self.interfaces_dict:
                info = self.interfaces_dict[interface]

                # Update status display
                status_text = f"Status: {info['status'].upper()}"
                if info['ip']:
                    status_text += f" | IP: {info['ip']}"
                if info['gateway']:
                    status_text += f" | Gateway: {info['gateway']}"

                self.interface_status.config(text=status_text)

                # Set suggested target IP
                if info['suggested_target']:
                    self.target_ip.set(info['suggested_target'])
                else:
                    self.target_ip.set("")

    def update_frequency_label(self, value):
        """Update the frequency label when scale changes"""
        self.frequency_label.config(text=str(int(float(value))))

    def update_threshold_label(self, value):
        """Update the threshold label when scale changes"""
        self.threshold_label.config(text=str(int(float(value))))

    def log_status(self, message):
        """Add a timestamped message to the status display"""
        timestamp = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
        full_message = f"[{timestamp}] {message}\n"

        self.status_text.config(state=tk.NORMAL)
        self.status_text.insert(tk.END, full_message)
        self.status_text.see(tk.END)
        self.status_text.config(state=tk.DISABLED)

    def send_email_alert(self, alert_data):
        """
        Send email alert notification
        Args:
            alert_data (dict): Dictionary containing alert information
        """
        try:
            # Validate email settings
            if not all([self.smtp_server.get(), self.smtp_username.get(), 
                       self.smtp_password.get(), self.email_from.get(), self.email_to.get()]):
                self.log_status("Email alert failed: Missing email configuration")
                return False

            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.email_from.get()
            msg['To'] = self.email_to.get()
            msg['Subject'] = f"Network Alert: {alert_data['interface']} Interface Down"

            # Create email body
            body = f"""
Network Interface Monitoring Alert

Interface: {alert_data['interface']}
Target IP: {alert_data['target']}
Time: {alert_data['timestamp'].strftime('%Y-%m-%d %I:%M:%S %p')}
Consecutive Failures: {alert_data['failures']}

The network interface has failed to respond to ping requests for the configured threshold.
"""

            if self.auto_restart.get():
                body += f"\nMonitoring will automatically restart in {self.restart_delay.get()} minutes."
            else:
                body += "\nMonitoring has been stopped. Please check the network connection and restart monitoring manually."

            msg.attach(MIMEText(body, 'plain'))

            # Bind to specific interface if specified
            smtp_interface = self.smtp_interface.get()
            if smtp_interface and smtp_interface in self.interfaces_dict:
                interface_ip = self.interfaces_dict[smtp_interface]['ip']
                if interface_ip:
                    # Create socket bound to specific interface
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.bind((interface_ip, 0))

                    # Connect to SMTP server
                    if self.smtp_use_tls.get():
                        server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get(), 
                                            local_hostname=None, source_address=(interface_ip, 0))
                        server.starttls()
                    else:
                        server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get(),
                                            local_hostname=None, source_address=(interface_ip, 0))
                else:
                    # Fallback to default connection
                    if self.smtp_use_tls.get():
                        server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get())
                        server.starttls()
                    else:
                        server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get())
            else:
                # Use default connection
                if self.smtp_use_tls.get():
                    server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get())
                    server.starttls()
                else:
                    server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get())

            # Login and send email
            server.login(self.smtp_username.get(), self.smtp_password.get())
            server.send_message(msg)
            server.quit()

            self.log_status(f"Email alert sent to {self.email_to.get()}")
            return True

        except Exception as e:
            self.log_status(f"Email alert failed: {str(e)}")
            return False

    def test_email_settings(self):
        """Test email configuration by sending a test email"""
        try:
            test_alert = {
                'interface': 'test',
                'target': '8.8.8.8',
                'timestamp': datetime.now(),
                'failures': 1
            }

            # Temporarily modify subject for test
            original_subject = "Network Alert: test Interface Down"

            # Create test message
            msg = MIMEMultipart()
            msg['From'] = self.email_from.get()
            msg['To'] = self.email_to.get()
            msg['Subject'] = "Test Email - Network Monitor Configuration"

            body = """
This is a test email from the Network Interface Ping Monitor.

If you receive this email, your email configuration is working correctly.

Test Details:
- SMTP Server: {}
- SMTP Port: {}
- TLS Enabled: {}
- From: {}
- To: {}
- Interface: {}

Time: {}
""".format(
                self.smtp_server.get(),
                self.smtp_port.get(),
                self.smtp_use_tls.get(),
                self.email_from.get(),
                self.email_to.get(),
                self.smtp_interface.get() or "Default",
                datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')
            )

            msg.attach(MIMEText(body, 'plain'))

            # Send using same logic as alert email
            smtp_interface = self.smtp_interface.get()
            if smtp_interface and smtp_interface in self.interfaces_dict:
                interface_ip = self.interfaces_dict[smtp_interface]['ip']
                if interface_ip:
                    if self.smtp_use_tls.get():
                        server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get(), 
                                            local_hostname=None, source_address=(interface_ip, 0))
                        server.starttls()
                    else:
                        server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get(),
                                            local_hostname=None, source_address=(interface_ip, 0))
                else:
                    if self.smtp_use_tls.get():
                        server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get())
                        server.starttls()
                    else:
                        server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get())
            else:
                if self.smtp_use_tls.get():
                    server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get())
                    server.starttls()
                else:
                    server = smtplib.SMTP(self.smtp_server.get(), self.smtp_port.get())

            server.login(self.smtp_username.get(), self.smtp_password.get())
            server.send_message(msg)
            server.quit()

            messagebox.showinfo("Test Email", "Test email sent successfully!")
            self.log_status("Test email sent successfully")

        except Exception as e:
            messagebox.showerror("Test Email Failed", f"Failed to send test email:\n{str(e)}")
            self.log_status(f"Test email failed: {str(e)}")

    def ping_host(self, host, interface=None):
        """
        Ping a host and return True if successful, False otherwise
        Args:
            host (str): IP address or hostname to ping
            interface (str): Network interface to use for ping (optional)
        Returns:
            bool: True if ping successful, False otherwise
        """
        try:
            cmd = ['ping', '-c', '1', '-W', '1']

            # Add interface specification if provided
            if interface:
                cmd.extend(['-I', interface])

            cmd.append(host)

            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            print(f"Ping error: {e}")
            return False

    def schedule_restart(self):
        """Schedule automatic restart of monitoring"""
        delay_minutes = self.restart_delay.get()
        delay_seconds = delay_minutes * 60

        self.log_status(f"Scheduling restart in {delay_minutes} minutes...")

        def restart_monitoring():
            self.log_status("Auto-restarting monitoring...")
            self.start_monitoring()

        self.restart_timer = threading.Timer(delay_seconds, restart_monitoring)
        self.restart_timer.start()

    def cancel_restart_timer(self):
        """Cancel any pending restart timer"""
        if self.restart_timer and self.restart_timer.is_alive():
            self.restart_timer.cancel()
            self.restart_timer = None
            self.log_status("Auto-restart cancelled")

    def monitor_network(self):
        """Main monitoring loop - runs in separate thread"""
        interface = self.selected_interface.get()
        target = self.target_ip.get()
        frequency = self.ping_frequency.get()
        threshold = self.failure_threshold.get()

        self.log_status(f"Started monitoring {interface} -> {target}")
        self.log_status(f"Ping frequency: {frequency}s, Failure threshold: {threshold}")

        self.consecutive_failures = 0

        while self.monitoring:
            # Perform ping test using specific interface
            if self.ping_host(target, interface):
                # Ping successful
                if self.consecutive_failures > 0:
                    self.log_status(f"Connection restored to {target} via {interface}")
                    self.consecutive_failures = 0
                else:
                    self.log_status(f"Ping successful: {target} via {interface}")
            else:
                # Ping failed
                self.consecutive_failures += 1
                self.log_status(f"Ping failed: {target} via {interface} (Failure {self.consecutive_failures}/{threshold})")

                # Check if we've reached the failure threshold
                if self.consecutive_failures >= threshold:
                    # Create alert data
                    alert_data = {
                        'interface': interface,
                        'target': target,
                        'timestamp': datetime.now(),
                        'failures': self.consecutive_failures
                    }

                    # Send alerts based on configuration
                    if self.alert_popup.get():
                        self.alert_queue.put(alert_data)

                    if self.alert_email.get():
                        self.send_email_alert(alert_data)

                    # Stop monitoring
                    self.log_status("Alert triggered - stopping monitoring")
                    self.monitoring = False

                    # Update UI and handle restart in main thread
                    self.root.after(0, lambda: self.handle_alert_triggered())
                    break

            # Wait for next ping cycle
            time.sleep(frequency)

        if self.monitoring:  # Only log if stopped normally (not by alert)
            self.log_status("Monitoring stopped")

    def handle_alert_triggered(self):
        """Handle UI updates and restart scheduling after alert (runs in main thread)"""
        # Update UI
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.interface_combo.config(state="readonly")

        # Schedule restart if enabled
        if self.auto_restart.get():
            self.schedule_restart()

    def start_monitoring(self):
        """Start the network monitoring process"""
        # Cancel any pending restart
        self.cancel_restart_timer()

        # Validate inputs
        if not self.selected_interface.get():
            messagebox.showerror("Error", "Please select a network interface")
            return

        if not self.target_ip.get():
            messagebox.showerror("Error", "Please enter a target IP address")
            return

        # Validate alert configuration
        if not self.alert_popup.get() and not self.alert_email.get():
            messagebox.showerror("Error", "Please select at least one alert method (popup or email)")
            return

        # Validate email settings if email alerts are enabled
        if self.alert_email.get():
            if not all([self.smtp_server.get(), self.smtp_username.get(), 
                       self.smtp_password.get(), self.email_from.get(), self.email_to.get()]):
                messagebox.showerror("Error", "Please configure all email settings before enabling email alerts")
                return

        # Start monitoring
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_network, daemon=True)
        self.monitor_thread.start()

        # Update UI
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.interface_combo.config(state=tk.DISABLED)

    def stop_monitoring(self):
        """Stop the network monitoring process"""
        self.monitoring = False
        self.cancel_restart_timer()

        # Update UI
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.interface_combo.config(state="readonly")

    def show_alert(self, alert_data):
        """
        Display an alert window for network failure
        Args:
            alert_data (dict): Dictionary containing alert information
        """
        alert_window = tk.Toplevel(self.root)
        alert_window.title("Network Alert")
        alert_window.geometry("450x400")  # Increased height for restart info
        alert_window.resizable(False, False)

        # Make alert window modal and always on top
        alert_window.transient(self.root)
        alert_window.grab_set()
        alert_window.attributes('-topmost', True)

        # Center the alert window
        alert_window.geometry("+{}+{}".format(
            int(alert_window.winfo_screenwidth()/2 - 225),
            int(alert_window.winfo_screenheight()/2 - 200)
        ))

        # Alert content with proper padding
        main_frame = ttk.Frame(alert_window, padding="25")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Alert icon and title
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(title_frame, text="⚠️", font=("Arial", 28)).pack(side=tk.LEFT)
        ttk.Label(title_frame, text="Network Interface Down", 
                 font=("Arial", 16, "bold")).pack(side=tk.LEFT, padx=(15, 0))

        # Alert details with better spacing
        details_frame = ttk.Frame(main_frame)
        details_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 25))

        # Create labels with consistent spacing
        details = [
            f"Interface: {alert_data['interface']}",
            f"Target IP: {alert_data['target']}",
            f"Time: {alert_data['timestamp'].strftime('%Y-%m-%d %I:%M:%S %p')}",
            f"Consecutive Failures: {alert_data['failures']}"
        ]

        for detail in details:
            ttk.Label(details_frame, text=detail, 
                     font=("Arial", 11)).pack(anchor=tk.W, pady=5)

        # Information about monitoring status
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=(15, 25))

        ttk.Label(info_frame, text="Monitoring has been stopped.", 
                 font=("Arial", 10), foreground="blue").pack(anchor=tk.W, pady=2)

        if self.auto_restart.get():
            ttk.Label(info_frame, text=f"Auto-restart scheduled in {self.restart_delay.get()} minutes.", 
                     font=("Arial", 10), foreground="green").pack(anchor=tk.W, pady=2)
        else:
            ttk.Label(info_frame, text="Click 'Start Monitoring' to resume.", 
                     font=("Arial", 10), foreground="blue").pack(anchor=tk.W, pady=2)

        # OK button with proper sizing
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))

        ok_button = ttk.Button(button_frame, text="OK", 
                              command=alert_window.destroy,
                              width=15)
        ok_button.pack(anchor=tk.CENTER)

        # Focus on OK button
        ok_button.focus_set()

        # Bind Enter and Escape keys to OK button
        alert_window.bind('<Return>', lambda e: alert_window.destroy())
        alert_window.bind('<Escape>', lambda e: alert_window.destroy())

    def check_alerts(self):
        """Check for queued alerts and display them"""
        try:
            while True:
                alert_data = self.alert_queue.get_nowait()
                self.show_alert(alert_data)
        except queue.Empty:
            pass

        # Schedule next check
        self.root.after(1000, self.check_alerts)

    def run(self):
        """Start the application main loop"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.stop_monitoring()
            self.cancel_restart_timer()
            sys.exit(0)

def main():
    """Main entry point for the application"""
    # Check if running on Linux (Raspberry Pi OS)
    if sys.platform != 'linux':
        print("Warning: This application is designed for Raspberry Pi OS (Linux)")

    # Create and run the application
    app = NetworkMonitor()
    app.run()

if __name__ == "__main__":
    main()
