import socket
import smtplib
from datetime import datetime, timedelta
import time
import sys
import os
import csv
import threading
from collections import deque
from ipaddress import ip_address, ip_network
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from colorama import Fore, init
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint
from rich.console import Console
from rich.table import Table
from rich.live import Live
from scapy.all import sniff, IP, TCP, UDP
from dotenv import load_dotenv
import requests

# Initialize libraries
init(autoreset=True)
console = Console()
load_dotenv()

# Global lists
blacklist_ranges = []
whitelist_ranges = []

# Load environment variables
smtp_server = os.getenv("SMTP_SERVER")
smtp_port = os.getenv("SMTP_PORT")
email_address = os.getenv("EMAIL_ADDRESS")
email_password = os.getenv("EMAIL_PASSWORD")
recipient_email = os.getenv("RECIPIENT_EMAIL")
ENABLE_GEOLOCATION = os.getenv("GEOLocate", "false").lower() == "true"

# CSV Log file
LOG_FILE = "firewall_logs.csv"
CSV_HEADERS = ["Timestamp", "IP Address", "Status", "Country", "City"]

# Ensure CSV exists and write headers
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)

# Validate IP range (CIDR)
def is_ip_in_range(ip, network):
    try:
        return ip_address(ip) in ip_network(network)
    except ValueError:
        return False

# Geolocation lookup
def get_geolocation(ip):
    if not ENABLE_GEOLOCATION:
        return "", ""
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get("country_name"), data.get("city")
    except Exception:
        pass
    return "Unknown", "Unknown"

# Log packet info to CSV
def log_to_csv(ip, status):
    country, city = get_geolocation(ip)
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), ip, status, country, city])

# Helper: Get service name from port
def get_service_name(port):
    services = {
        80: "HTTP",
        443: "HTTPS",
        53: "DNS",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        22: "SSH",
        3389: "RDP",
        21: "FTP",
        23: "Telnet",
        123: "NTP",
        161: "SNMP",
        500: "IKE",
        4500: "NAT-T",
    }
    return services.get(port, "Unknown")

# Packet callback
def process_packet(packet):
    if IP in packet:
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        # Detect protocol and port
        proto = "Unknown"
        dport = "N/A"
        service = "Unknown"

        if packet.haslayer(TCP):
            proto = "TCP"
            dport = packet[TCP].dport
            service = get_service_name(dport)
        elif packet.haslayer(UDP):
            proto = "UDP"
            dport = packet[UDP].sport
            service = get_service_name(dport)

        # Check if blacklisted or whitelisted
        is_blacklisted = any(is_ip_in_range(src_ip, r) for r in blacklist_ranges)
        is_whitelisted = any(is_ip_in_range(src_ip, r) for r in whitelist_ranges)

        # Log it
        log_status = "Blacklisted" if is_blacklisted else ("Whitelisted" if is_whitelisted else "Unrecognized")
        country, city = get_geolocation(src_ip)
        log_to_csv(src_ip, log_status)

        # Show packet in structured format
        display_packet(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            src_ip=src_ip,
            dst_ip=dst_ip,
            proto=f"{proto}/{dport} ({service})",
            location=f"{city}, {country}"
        )

        update_dashboard(src_ip, is_blacklisted, is_whitelisted)

# Display packet in structured block
def display_packet(timestamp, src_ip, dst_ip, proto, location):
    table = Table(box=None, show_header=False)
    table.add_column("Key", style="cyan")
    table.add_column("Value")

    table.add_row("Timestamp", timestamp)
    table.add_row("Detected", f"{src_ip} → {dst_ip}")
    table.add_row("Protocol", proto)
    table.add_row("Location", location)

    console.print(table)
    console.print("[✓] Email report scheduled: Next in 4m 32s\n")

# Dashboard update
recent_ips = deque(maxlen=5)
packet_table = Table(title="📡 Real-Time Packet Monitor")

def update_dashboard(ip, is_blacklisted, is_whitelisted):
    recent_ips.append((ip, is_blacklisted, is_whitelisted))
    packet_table.columns.clear()
    packet_table.title = f"🕒 Last Seen: {ip}"
    packet_table.add_column("Status", justify="left")
    for ip_str, bl, wl in recent_ips:
        if bl:
            packet_table.add_row(f"[red]🔴 Blacklisted IP: {ip_str}[/red]")
        elif wl:
            packet_table.add_row(f"[green]🟢 Whitelisted IP: {ip_str}[/green]")
        else:
            packet_table.add_row(f"[yellow]🟡 Unrecognized IP: {ip_str}[/yellow]")

# Export unrecognized IPs by time range
def export_ips_by_time_range(minutes=5, output_file="unrecognized_ips_recent.csv"):
    now = datetime.now()
    cutoff = now - timedelta(minutes=minutes)

    with open(LOG_FILE, "r") as infile, open(output_file, "w", newline="") as outfile:
        reader = csv.DictReader(infile)
        writer = csv.writer(outfile)
        writer.writerow(CSV_HEADERS)

        for row in reader:
            try:
                log_time = datetime.strptime(row["Timestamp"], "%Y-%m-%d %H:%M:%S")
                if log_time > cutoff and row["Status"] == "Unrecognized":
                    writer.writerow([
                        row["Timestamp"],
                        row["IP Address"],
                        row["Status"],
                        row["Country"],
                        row["City"]
                    ])
            except Exception:
                continue

    return output_file

# Export daily report
def export_daily_report(output_file="daily_unrecognized_ips.csv"):
    now = datetime.now()
    cutoff = now - timedelta(days=1)

    with open(LOG_FILE, "r") as infile, open(output_file, "w", newline="") as outfile:
        reader = csv.DictReader(infile)
        writer = csv.writer(outfile)
        writer.writerow(CSV_HEADERS)

        for row in reader:
            try:
                log_time = datetime.strptime(row["Timestamp"], "%Y-%m-%d %H:%M:%S")
                if log_time > cutoff and row["Status"] == "Unrecognized":
                    writer.writerow([
                        row["Timestamp"],
                        row["IP Address"],
                        row["Status"],
                        row["Country"],
                        row["City"]
                    ])
            except Exception:
                continue

    return output_file

# Send professional email
def send_professional_email(subject, attachment_path, ip_count, time_range):
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = email_address
    msg["To"] = recipient_email

    # Generate table rows
    table_rows = ""
    try:
        with open(attachment_path, "r") as f:
            lines = f.readlines()[1:]  # Skip header
            for line in lines[:10]:   # Show up to 10 rows in email
                parts = line.strip().split(",")
                if len(parts) >= 4:
                    table_rows += f"""
                    <tr>
                        <td>{parts[0]}</td>
                        <td>{parts[1]}</td>
                        <td>{parts[3]}</td>
                    </tr>
                    """
    except Exception as e:
        table_rows = "<tr><td colspan='3'>Error loading data</td></tr>"

    # Build HTML content
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6;">
        <div style="max-width: 600px; margin: auto; border: 1px solid #ddd; padding: 20px; border-radius: 8px;">
            <h2 style="color: #2c3e50;">🛡️ Firewall Report</h2>
            <p>Hi Admin,</p>
            <p>Here's a summary of network activity from the last {time_range}.</p>

            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                <strong>📊 Total Unrecognized IPs:</strong> {ip_count}<br/>
                <strong>🕒 Time Range:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} (approx.)
            </div>

            <h3>📋 Below are the unrecognized IPs detected:</h3>
            <table style="width:100%; border-collapse: collapse; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f0f0f0;">
                        <th style="border: 1px solid #ccc; padding: 8px;">Timestamp</th>
                        <th style="border: 1px solid #ccc; padding: 8px;">IP Address</th>
                        <th style="border: 1px solid #ccc; padding: 8px;">Country</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>

            <p style="margin-top: 20px;">📎 Full log attached as <strong>{os.path.basename(attachment_path)}</strong></p>

            <!-- Signature -->
            <div style="margin-top: 40px; border-top: 1px solid #eee; padding-top: 20px;">
                <p style="font-size: 12px; color: #666;">
                    This report was generated by<br>
                    <strong style="font-size: 15px;">Firewall Notifier</strong> — Simple. Secure. Smarter Defense.<br><br>
                    <a href="https://firewallnotifier.cyberfascinate.com" style="
                        display: inline-block;
                        padding: 6px 12px;
                        font-size: 12px;
                        background-color: #007BFF;
                        color: white !important;
                        text-decoration: none;
                        border-radius: 4px;
                        font-weight: normal;
                    ">Visit Website</a>
                    <br><br>
                    Maintained by <a href='mailto:contact@cyberfascinate.com' style='color: #007BFF; text-decoration: none;'>CyberFascinate</a> • MIT Licensed • Self-Hosted & Secure<br>
                    <a href='https://github.com/cyberfascinate/firewallnotifier' style='color: #007BFF; text-decoration: none;'>GitHub</a> • 
                    <a href='https://linkedin.com/in/cyberfascinate' style='color: #007BFF; text-decoration: none;'>LinkedIn</a>
                </p>
            </div>
        </div>
    </body>
    </html>
    """

    msg.attach(MIMEText(html_body, 'html'))

    # Attach file
    try:
        with open(attachment_path, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(attachment_path)}")
            msg.attach(part)
    except Exception as e:
        console.print(f"[!] Failed to attach file: {e}")

    # Send email
    try:
        with smtplib.SMTP(smtp_server, int(smtp_port)) as server:
            server.starttls()
            server.login(email_address, email_password)
            server.sendmail(email_address, recipient_email, msg.as_string())
        console.print(f"[+] Sent professional report: {subject}")
    except Exception as e:
        console.print(f"[!] Failed to send email: {e}")

# Schedule periodic reports
def schedule_periodic_report(interval_minutes):
    def job():
        filename = export_ips_by_time_range(
            minutes=interval_minutes,
            output_file=f"unrecognized_{interval_minutes}min.csv"
        )
        try:
            with open(filename, "r") as f:
                ip_count = sum(1 for _ in f) - 1  # Subtract header
        except:
            ip_count = 0

        send_professional_email(
            subject=f"🕒 Firewall Report – {ip_count} Unrecognized IPs ({interval_minutes} Min)",
            attachment_path=filename,
            ip_count=ip_count,
            time_range=f"{interval_minutes} minutes"
        )
        threading.Timer(interval_minutes * 60, job).start()

    job()  # First run immediately

# Schedule daily report
def schedule_daily_report():
    def job():
        filename = export_daily_report()
        try:
            with open(filename, "r") as f:
                ip_count = sum(1 for _ in f) - 1
        except:
            ip_count = 0

        send_professional_email(
            subject="📆 Daily Firewall Report – " + str(ip_count) + " Unrecognized IPs",
            attachment_path=filename,
            ip_count=ip_count,
            time_range="24 hours"
        )

        # Schedule again after 24 hours
        threading.Timer(86400, job).start()

    # Schedule first run at midnight
    now = datetime.now()
    next_run = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    delay = (next_run - now).total_seconds()
    threading.Timer(delay, job).start()

# Handle exit gracefully
def signal_handler(sig, frame):
    console.print("\n[!] Stopping packet capture.")
    unrecognized_file = export_ips_by_time_range(5, "unrecognized_exit_report.csv")
    try:
        ip_count = sum(1 for _ in open(unrecognized_file)) - 1
    except:
        ip_count = 0
    send_professional_email(
        subject="🛑 Firewall Session Ended – Exit Report",
        attachment_path=unrecognized_file,
        ip_count=ip_count,
        time_range="last 5 mins"
    )
    sys.exit(0)

# CLI Banner
def show_startup_banner():
    console.rule("[bold blue]Firewall Notifier — Simple. Secure. Smarter Defense.")
    console.print("")
    console.print("[*] Initializing Firewall Notifier v1.0.0...\n")
    console.print("[+] Loading configuration...")

# Main function
def main():
    global blacklist_ranges, whitelist_ranges

    show_startup_banner()

    print("Choose a filtering mode:")
    print("1. Blacklist")
    print("2. Whitelist")
    print("3. Both")
    print("4. None")
    mode_choice = input("Enter choice [1-4]: ").strip()

    if mode_choice == '1':
        print("Blacklist mode selected.")
        while True:
            ip = input("Enter Blacklist IP/CIDR (type 'done' to finish): ").strip()
            if ip.lower() == 'done':
                break
            if '/' not in ip:
                ip += '/32'
            blacklist_ranges.append(ip)
    elif mode_choice == '2':
        print("Whitelist mode selected.")
        while True:
            ip = input("Enter Whitelist IP/CIDR (type 'done' to finish): ").strip()
            if ip.lower() == 'done':
                break
            if '/' not in ip:
                ip += '/32'
            whitelist_ranges.append(ip)
    elif mode_choice == '3':
        print("Both Blacklist and Whitelist mode selected.")
        print("Enter Blacklist IPs:")
        while True:
            ip = input("Enter Blacklist IP/CIDR (type 'done' to finish): ").strip()
            if ip.lower() == 'done':
                break
            if '/' not in ip:
                ip += '/32'
            blacklist_ranges.append(ip)
        print("Enter Whitelist IPs:")
        while True:
            ip = input("Enter Whitelist IP/CIDR (type 'done' to finish): ").strip()
            if ip.lower() == 'done':
                break
            if '/' not in ip:
                ip += '/32'
            whitelist_ranges.append(ip)
    elif mode_choice == '4':
        print("No filtering mode selected.")

    # Show config summary
    console.print(f"[+] Blacklist loaded: {len(blacklist_ranges)} CIDR ranges")
    console.print(f"[+] Whitelist loaded: {len(whitelist_ranges)} CIDR ranges\n")
    console.print("[!] Starting packet capture on [bold]any[/bold] interface...\n")

    # Start scheduled reports
    schedule_periodic_report(1)
    schedule_periodic_report(5)
    schedule_periodic_report(10)
    schedule_periodic_report(15)
    schedule_daily_report()

    # Start live dashboard
    with Live(packet_table, refresh_per_second=1):
        sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()