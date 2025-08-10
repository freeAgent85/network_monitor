# Network Monitor for Raspberry Pi OS

A comprehensive network monitoring application designed for Raspberry Pi OS that monitors network connectivity by pinging target addresses and provides flexible alerting options when network failures occur.

## Overview

```Network Monitor``` is a Python-based GUI application that continuously monitors network connectivity through specific network interfaces. It detects network outages by tracking consecutive ping failures and can alert users through popup windows, email notifications, or both. The application features automatic restart capabilities and comprehensive configuration options for various network monitoring scenarios.

The author's intended use for this application is to monitor the Pi's WiFi network connectivity in order to detect intentional WiFi disruptions, such as those created by a WiFi jammer. Thus, it is assumed that the user's Raspberry Pi has network connectivity on both wired and wireless interfaces.

## Features

### Core Monitoring Capabilities
- **Multi-Interface Support**: Detects and monitors all available network interfaces (primary and secondary)
- **Interface-Specific Pinging**: Uses ```ping -I interface``` to ensure pings go through the selected interface
- **Intelligent Target Selection**: Automatically suggests gateway IPs for the local network
- **Real-Time Status Display**: Shows interface status, IP addresses, and gateway information
- **Configurable Ping Parameters**: Adjustable ping frequency (1-60 seconds) and failure thresholds (1-10 consecutive failures)

### Alert System
- **Dual Alert Methods**: Choose between popup windows, email notifications, or both
- **Popup Alerts**: Modal windows with comprehensive failure information
- **Email Notifications**: SMTP-based email alerts with detailed network failure reports
- **Interface-Specific SMTP**: Configure which network interface to use for sending email alerts
- **Alert Content**: Includes interface name, target IP, timestamp, failure count, and monitoring status

### Automatic Recovery
- **Auto-Restart Monitoring**: Automatically resume monitoring after alerts with configurable delays
- **Flexible Restart Delays**: Choose from 1, 5, 10, 15, 30, or 60-minute restart intervals
- **Manual Override**: Stop and start monitoring manually at any time

### Email Configuration
- **SMTP Server Support**: Compatible with Gmail, Outlook, and other SMTP providers
- **TLS Encryption**: Secure email transmission with optional TLS support
- **Authentication**: Username/password authentication for SMTP servers
- **Test Functionality**: Built-in email testing to verify configuration
- **Network Interface Binding**: Send emails through specific network interfaces

## System Requirements

- **Operating System**: Raspberry Pi OS (Linux)
- **Python Version**: Python 3.6 or higher
- **Required Python Packages**:
  - ```tkinter``` (usually included with Python)
  - ```netifaces```
  - ```subprocess``` (standard library)
  - ```threading``` (standard library)
  - ```smtplib``` (standard library)
  - ```email``` (standard library)

## Installation

1. **Install Required Dependencies**:
   ```bash
   sudo apt update
   sudo apt install python3-tk python3-pip
   pip3 install netifaces
   ```

2. **Download the Application**:
   Save the script as ```network_monitor.py``` in your desired directory.

3. **Make Executable** (optional):
   ```bash
   chmod +x network_monitor.py
   ```

## Usage

### Starting the Application

```bash
python3 network_monitor.py
```

### Configuration

#### 1. Monitoring Tab
- **Network Interface**: Select the interface to monitor from the dropdown
  - Interfaces show status indicators (🟢 for up, 🔴 for down)
  - IP addresses are displayed for active interfaces
  - Use "Refresh" button to update interface list
- **Target IP Address**: Specify the IP to ping (auto-populated with suggested gateway)
- **Ping Frequency**: Set how often to ping (1-60 seconds, default: 10)
- **Failure Threshold**: Number of consecutive failures before triggering alert (1-10, default: 3)

#### 2. Alert Settings Tab
- **Alert Methods**:
  - ☑️ Show popup window
  - ☑️ Send email notification
- **Auto-Restart Settings**:
  - ☑️ Automatically restart monitoring after alert
  - Select restart delay: 1, 5, 10, 15, 30, or 60 minutes

#### 3. Email Settings Tab
- **SMTP Server Settings**:
  - SMTP Server: e.g., ```smtp.gmail.com```
  - Port: e.g., ```587``` for TLS, ```465``` for SSL
  - ☑️ Use TLS encryption
  - Network Interface: Choose which interface to use for SMTP
- **Authentication**:
  - Username: Your email account username
  - Password: Your email account password or app-specific password
- **Email Addresses**:
  - From: Sender email address
  - To: Recipient email address

### Operation

1. **Configure Settings**: Set up monitoring parameters, alert preferences, and email settings (if using email alerts)

2. **Test Email** (optional): Click "Test Email" button to verify email configuration

3. **Start Monitoring**: Click "Start Monitoring" to begin network monitoring
   - The interface dropdown becomes disabled during monitoring
   - Status messages appear in the log window
   - Ping results are logged with timestamps

4. **Alert Handling**: When consecutive failures reach the threshold:
   - Popup alert appears (if enabled) with failure details
   - Email notification sent (if enabled) with comprehensive report
   - Monitoring stops automatically
   - Auto-restart timer begins (if enabled)

5. **Manual Control**: Use "Stop Monitoring" to halt monitoring at any time

### Email Configuration Examples

#### Gmail Configuration
- **SMTP Server**: ```smtp.gmail.com```
- **Port**: ```587```
- **TLS**: ✅ Enabled
- **Username**: ```your-email@gmail.com```
- **Password**: Use App Password (not regular password)

#### Outlook/Hotmail Configuration
- **SMTP Server**: ```smtp-mail.outlook.com```
- **Port**: ```587```
- **TLS**: ✅ Enabled
- **Username**: ```your-email@outlook.com```
- **Password**: Your account password

## Alert Information

Both popup and email alerts include:
- **Interface Name**: The monitored network interface
- **Target IP**: The IP address being pinged
- **Timestamp**: Date and time when the alert was triggered
- **Consecutive Failures**: Number of failed ping attempts
- **Monitoring Status**: Information about automatic restart (if enabled)

## Troubleshooting

### Common Issues

1. **No Interfaces Detected**:
   - Ensure network interfaces are properly configured
   - Run with sudo if permission issues occur
   - Check that ```netifaces``` package is installed

2. **Email Alerts Not Working**:
   - Verify SMTP server settings
   - Check username/password credentials
   - For Gmail, use App Passwords instead of regular password
   - Test email configuration using the "Test Email" button
   - Ensure selected SMTP interface has internet connectivity

3. **Ping Failures**:
   - Verify target IP is reachable
   - Check that selected interface is active
   - Ensure proper network routing for the interface

4. **Permission Errors**:
   - Some network operations may require elevated privileges
   - Try running with ```sudo python3 network_monitor.py```

### Log Analysis

The status window provides detailed logging:
- Successful pings are logged with interface and target information
- Failed pings show failure count and threshold progress
- Email sending status is reported
- Auto-restart scheduling is logged with countdown information

## Security Considerations

- **Email Passwords**: Use app-specific passwords when available (Gmail, Outlook)
- **Network Binding**: SMTP interface binding helps ensure emails are sent through intended network paths
- **Local Storage**: Email credentials are stored in memory only during application runtime
