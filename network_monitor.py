import nmap
import sqlite3
import time
from pythonping import ping
from scapy.all import sniff, Ether, IP, ARP, DHCP
import configparser
import smtplib
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.application import MIMEApplication
import os
import pandas as pd
from sklearn.ensemble import IsolationForest
import geoip2.database
from mac_vendor_lookup import MacLookup
import socket
import requests

# Read configuration
config = configparser.ConfigParser()
config.read('config.ini')

# Access settings
network_range = config['Network']['range']
interface = config['Network']['interface']
smtp_server = config['Email']['smtp_server']
smtp_port = int(config['Email']['smtp_port'])
smtp_user = config['Email']['sender']
smtp_password = config['Email']['password']
email_receivers = config['Email']['receivers'].split(',')
passive_timeout = int(config['Scan']['passive_timeout'])
ids_log_file = config['IDS']['log_file']
abuseipdb_api_key = config['ThreatFeeds']['abuseipdb_api_key']
geolite2_db_path = config['GeoIP']['geolite2_db']

# Initialize global variables
mac_lookup = MacLookup()
mac_lookup.update_vendors()  # Update local vendor database
reader = geoip2.database.Reader(geolite2_db_path)

# Passive device fingerprinting
def passive_fingerprint(timeout=60):
    print("Starting passive fingerprinting...")
    devices = {}
    traffic_data = {}

    def packet_handler(packet):
        if packet.haslayer(Ether):
            mac = packet[Ether].src
            if mac not in devices:
                devices[mac] = {'mac': mac}

            # Vendor Lookup
            devices[mac]['vendor'] = get_vendor(mac)

            # Update IP address
            if packet.haslayer(IP):
                devices[mac]['ip'] = packet[IP].src

                # Bandwidth Monitoring
                packet_size = len(packet)
                if mac not in traffic_data:
                    traffic_data[mac] = {'bytes': 0, 'protocols': {}}
                traffic_data[mac]['bytes'] += packet_size

                # Protocol Analysis
                proto = packet[IP].proto
                if proto not in traffic_data[mac]['protocols']:
                    traffic_data[mac]['protocols'][proto] = 0
                traffic_data[mac]['protocols'][proto] += 1

                # External Traffic Monitoring
                dst_ip = packet[IP].dst
                if not is_private_ip(dst_ip):
                    try:
                        response = reader.city(dst_ip)
                        country = response.country.name
                        city = response.city.name
                        latitude = response.location.latitude
                        longitude = response.location.longitude

                        if 'external_traffic' not in devices[mac]:
                            devices[mac]['external_traffic'] = []
                        devices[mac]['external_traffic'].append({
                            'dst_ip': dst_ip,
                            'country': country,
                            'city': city,
                            'latitude': latitude,
                            'longitude': longitude,
                            'timestamp': time.time()
                        })
                    except:
                        pass

            # Extract DHCP options
            if packet.haslayer(DHCP):
                options = packet[DHCP].options
                for opt in options:
                    if opt[0] == 'hostname':
                        devices[mac]['hostname'] = opt[1].decode() if isinstance(opt[1], bytes) else opt[1]
                    elif opt[0] == 'vendor_class_id':
                        devices[mac]['vendor'] = opt[1].decode() if isinstance(opt[1], bytes) else opt[1]
                    elif opt[0] == 'requested_addr':
                        devices[mac]['requested_ip'] = opt[1]
                    elif opt[0] == 'message-type':
                        devices[mac]['dhcp_message_type'] = opt[1]
            else:
                devices[mac]['hostname'] = devices[mac].get('hostname', 'Unknown')

    sniff(prn=packet_handler, store=0, timeout=timeout, iface=interface)
    # Add traffic data to devices
    for mac in devices:
        devices[mac]['bandwidth_usage'] = traffic_data.get(mac, {}).get('bytes', 0)
        devices[mac]['protocols'] = traffic_data.get(mac, {}).get('protocols', {})
    return list(devices.values())

def is_private_ip(ip):
    return ip.startswith('10.') or ip.startswith('172.') or ip.startswith('192.168.')

def get_vendor(mac):
    try:
        vendor = mac_lookup.lookup(mac)
        return vendor
    except:
        return 'Unknown'

# Scan the network for devices
def scan_network():
    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments='-O -sV')  # OS detection and service/version detection
    devices = []
    for host in nm.all_hosts():
        try:
            mac = nm[host]['addresses'].get('mac', 'N/A')
            device_info = {
                'ip': host,
                'mac': mac,
                'hostname': nm[host].hostname(),
                'vendor': get_vendor(mac),
                'os': nm[host]['osmatch'][0]['name'] if 'osmatch' in nm[host] and nm[host]['osmatch'] else 'Unknown',
                'ports': scan_ports(host)  # Scanning ports separately
            }
            devices.append(device_info)
        except Exception as e:
            print(f"Error scanning host {host}: {e}")
    return devices

# Scan open ports on a device
def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-sV -Pn')  # Service/version detection, skip host discovery
    ports_info = []
    try:
        if 'tcp' in nm[ip]:
            for port in nm[ip]['tcp']:
                port_info = {
                    'ip': ip,
                    'port': port,
                    'state': nm[ip]['tcp'][port]['state'],
                    'name': nm[ip]['tcp'][port]['name'],
                    'product': nm[ip]['tcp'][port]['product'],
                    'version': nm[ip]['tcp'][port]['version'],
                    'extrainfo': nm[ip]['tcp'][port]['extrainfo'],
                    'banner': grab_banner(ip, port)
                }
                ports_info.append(port_info)
    except KeyError:
        pass
    return ports_info

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner
    except:
        return ''

# Ping the devices to check their status
def ping_device(ip):
    try:
        response = ping(ip, count=1, timeout=1)
        return response.success()
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        return False

# Ping all devices and update their reachability status
def ping_devices(devices):
    for device in devices:
        device['reachable'] = ping_device(device['ip'])

# Merge passive and active scan results
def merge_devices(passive_devices, active_devices):
    devices_dict = {}

    # Add passive devices
    for device in passive_devices:
        mac = device['mac']
        devices_dict[mac] = device

    # Update with active scan data
    for device in active_devices:
        mac = device['mac']
        if mac in devices_dict:
            devices_dict[mac].update(device)
        else:
            devices_dict[mac] = device

    return list(devices_dict.values())

# Update the database with scanned devices
def update_database(devices):
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()

    # Load threat feeds
    c.execute('SELECT ip FROM threat_feeds')
    threat_ips = set([row[0] for row in c.fetchall()])

    for device in devices:
        mac = device['mac']
        # Check if device exists
        c.execute('SELECT * FROM devices WHERE mac = ?', (mac,))
        result = c.fetchone()
        is_new_device = result is None

        # Insert or update device
        c.execute('''
            INSERT OR IGNORE INTO devices (mac, hostname, vendor, first_seen)
            VALUES (?, ?, ?, ?)
        ''', (mac, device.get('hostname', 'Unknown'), device.get('vendor', 'Unknown'), time.time()))

        # Insert device history
        c.execute('''
            INSERT INTO device_history (mac, ip, os, bandwidth_usage, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            mac,
            device.get('ip', 'Unknown'),
            device.get('os', 'Unknown'),
            device.get('bandwidth_usage', 0),
            time.time()
        ))

        # Insert open ports
        for port_info in device.get('ports', []):
            c.execute('''
                INSERT INTO open_ports (mac, ip, port, state, name, product, version, extrainfo, banner, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                mac,
                port_info['ip'],
                port_info['port'],
                port_info['state'],
                port_info['name'],
                port_info['product'],
                port_info['version'],
                port_info['extrainfo'],
                port_info['banner'],
                time.time()
            ))

        # Insert protocol usage
        for proto_num, count in device.get('protocols', {}).items():
            protocol_name = get_protocol_name(proto_num)
            c.execute('''
                INSERT INTO protocol_usage (mac, protocol, packet_count, timestamp)
                VALUES (?, ?, ?, ?)
            ''', (
                mac,
                protocol_name,
                count,
                time.time()
            ))

        # Insert external traffic
        for ext_traffic in device.get('external_traffic', []):
            c.execute('''
                INSERT INTO external_traffic (mac, dst_ip, country, city, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                mac,
                ext_traffic['dst_ip'],
                ext_traffic['country'],
                ext_traffic['city'],
                ext_traffic['timestamp']
            ))

        # If new device, trigger an alert
        if is_new_device:
            alert_new_device(device)

        # Check if device IP is in threat feeds
        if device.get('ip') in threat_ips:
            alert_threat_detected(device)

    conn.commit()
    conn.close()

def get_protocol_name(proto_num):
    try:
        proto_name = socket.getservbyport(proto_num)
        return proto_name
    except:
        # Map protocol numbers to names manually if necessary
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            # Add more as needed
        }
        return protocols.get(proto_num, str(proto_num))

# Alert function for new devices
def alert_new_device(device):
    subject = f"New Device Detected on Network: {device['mac']}"
    body = f"""
A new device has joined the network.

MAC Address: {device['mac']}
IP Address: {device.get('ip', 'Unknown')}
Hostname: {device.get('hostname', 'Unknown')}
Vendor: {device.get('vendor', 'Unknown')}
OS: {device.get('os', 'Unknown')}

Detected at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}
"""
    send_email_alert(subject, body)

# Alert function for IDS events
def parse_ids_alerts():
    ids_alerts = []
    if not os.path.exists(ids_log_file):
        return ids_alerts
    with open(ids_log_file, 'r') as f:
        for line in f:
            alert = line.strip()
            ids_alerts.append(alert)
    return ids_alerts

def alert_ids_event(alert):
    subject = "IDS Alert Detected on Network"
    body = f"""
An IDS alert has been detected:

{alert}

Detected at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}
"""
    send_email_alert(subject, body)

# Alert function for anomalies
def alert_anomalies(anomalies):
    subject = "Anomalies Detected in Network Usage"
    body = f"""
Anomalies have been detected in network usage:

{anomalies.to_string(index=False)}

Detected at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}
"""
    send_email_alert(subject, body)

# Alert function for threat detection
def alert_threat_detected(device):
    subject = "Threat Detected on Network Device"
    body = f"""
A device on your network is communicating with a known malicious IP.

Device MAC: {device['mac']}
IP Address: {device.get('ip', 'Unknown')}
Hostname: {device.get('hostname', 'Unknown')}

Action is recommended.

Detected at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}
"""
    send_email_alert(subject, body)

# Send email alert
def send_email_alert(subject, body, attachment_path=None):
    sender = smtp_user
    receivers = email_receivers

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(receivers)

    # Attach file if provided
    if attachment_path:
        with open(attachment_path, 'rb') as f:
            file_data = f.read()
        if attachment_path.endswith('.png'):
            image = MIMEImage(file_data, name=os.path.basename(attachment_path))
            msg.attach(image)
        else:
            attachment = MIMEApplication(file_data, Name=os.path.basename(attachment_path))
            msg.attach(attachment)

    try:
        smtp_obj = smtplib.SMTP(smtp_server, smtp_port)
        smtp_obj.starttls()
        smtp_obj.login(smtp_user, smtp_password)
        smtp_obj.sendmail(sender, receivers, msg.as_string())
        smtp_obj.quit()
        print("Successfully sent email alert")
    except Exception as e:
        print(f"Error: unable to send email. {e}")

# Anomaly Detection
def detect_anomalies():
    df = load_historical_data()
    if df.empty:
        return pd.DataFrame()
    # Feature selection
    features = df[['bandwidth_usage']]
    # Handle missing values
    features = features.fillna(0)
    # Train Isolation Forest
    clf = IsolationForest(contamination=0.01)
    clf.fit(features)
    df['anomaly'] = clf.predict(features)
    anomalies = df[df['anomaly'] == -1]
    return anomalies

def load_historical_data():
    conn = sqlite3.connect('network_devices.db')
    df = pd.read_sql_query('SELECT * FROM device_history', conn)
    conn.close()
    return df

# Update threat feeds from AbuseIPDB
def update_threat_feeds():
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_api_key
    }
    response = requests.get('https://api.abuseipdb.com/api/v2/blacklist', headers=headers)
    data = response.json()
    ips = [item['ipAddress'] for item in data['data']]

    # Store in database
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    c.execute('DELETE FROM threat_feeds')
    for ip in ips:
        c.execute('INSERT INTO threat_feeds (ip) VALUES (?)', (ip,))
    conn.commit()
    conn.close()
    print("Threat feeds updated.")

# Main function
def main():
    # Update threat feeds (you can also schedule this separately)
    update_threat_feeds()

    # Passive fingerprinting and bandwidth/protocol monitoring
    passive_devices = passive_fingerprint(timeout=passive_timeout)
    # Active scanning
    active_devices = scan_network()
    # Merge devices
    devices = merge_devices(passive_devices, active_devices)
    # Ping devices
    ping_devices(devices)
    # Update database and alert on new devices and threats
    update_database(devices)
    # Parse IDS alerts
    ids_alerts = parse_ids_alerts()
    if ids_alerts:
        for alert in ids_alerts:
            alert_ids_event(alert)
    # Anomaly detection
    anomalies = detect_anomalies()
    if not anomalies.empty:
        alert_anomalies(anomalies)
    # Generate reports (optional)
    # generate_report()  # Uncomment if you wish to generate reports here

if __name__ == '__main__':
    main()