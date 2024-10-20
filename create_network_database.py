import sqlite3

def setup_database():
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()

    # Create devices table
    c.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            hostname TEXT,
            vendor TEXT,
            first_seen TIMESTAMP
        )
    ''')

    # Create device_history table
    c.execute('''
        CREATE TABLE IF NOT EXISTS device_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            ip TEXT,
            os TEXT,
            bandwidth_usage INTEGER,
            timestamp TIMESTAMP,
            FOREIGN KEY(mac) REFERENCES devices(mac)
        )
    ''')

    # Create open_ports table
    c.execute('''
        CREATE TABLE IF NOT EXISTS open_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            ip TEXT,
            port INTEGER,
            state TEXT,
            name TEXT,
            product TEXT,
            version TEXT,
            extrainfo TEXT,
            banner TEXT,
            timestamp TIMESTAMP,
            FOREIGN KEY(mac) REFERENCES devices(mac)
        )
    ''')

    # Create protocol_usage table
    c.execute('''
        CREATE TABLE IF NOT EXISTS protocol_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            protocol TEXT,
            packet_count INTEGER,
            timestamp TIMESTAMP,
            FOREIGN KEY(mac) REFERENCES devices(mac)
        )
    ''')

    # Create external_traffic table
    c.execute('''
        CREATE TABLE IF NOT EXISTS external_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            dst_ip TEXT,
            country TEXT,
            city TEXT,
            timestamp TIMESTAMP,
            FOREIGN KEY(mac) REFERENCES devices(mac)
        )
    ''')

    # Create threat_feeds table
    c.execute('''
        CREATE TABLE IF NOT EXISTS threat_feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print("Database setup complete.")

if __name__ == '__main__':
    setup_database()