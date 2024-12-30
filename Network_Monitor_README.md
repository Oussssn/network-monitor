# Network Monitor

A Python-based network traffic analyzer with intrusion detection capabilities that performs real-time monitoring and generates detailed logs.

## Features

### Real-time Traffic Analysis
- Packet capturing
- Protocol identification
- Port monitoring
- Connection tracking

### Intrusion Detection
- Port scan detection
- Connection flood alerts
- Suspicious IP tracking
- Real-time threat alerts

### Cross-Platform Support
- Windows compatibility
- Linux compatibility
- Interface auto-detection
- Privilege checking

### Logging System
- Automated log rotation
- Traffic activity logging
- Security alerts logging
- Custom log directories

---

## Requirements
- Python 3.x
- `scapy` library
- Administrator/Root privileges
- Npcap (Windows only)

---

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Oussssn/network-monitor.git
   cd network-monitor
   ```

2. Install dependencies:
   ```bash
   pip install scapy
   ```

3. Windows users only:
   - Download and install Npcap from: [Npcap Download](https://npcap.com/#download)

---

## Usage

### List available interfaces:

#### Windows (as Administrator):
```bash
python network_monitor.py -l
```

#### Linux:
```bash
sudo python3 network_monitor.py -l
```

### Start monitoring:

#### Windows (as Administrator):
```bash
python network_monitor.py -i "Wi-Fi"
```

#### Linux:
```bash
sudo python3 network_monitor.py -i eth0
```

The monitor will:
- Display real-time traffic
- Generate logs in the `logs` directory
- Alert for suspicious activities

---

## Customization Options

### Threshold Modifications
You can modify the detection thresholds in the code:
```python
# In NetworkMonitor class
self.CONNECTION_THRESHOLD = 50  # Change for connection flood sensitivity
self.PORT_SCAN_THRESHOLD = 10   # Change for port scan sensitivity
```

### Logging Customization
Modify logging settings:
```python
# In setup_logging method
traffic_handler = RotatingFileHandler(
    os.path.join(log_dir, 'traffic.log'),
    maxBytes=10*1024*1024,  # Change max file size (default 10MB)
    backupCount=5           # Change number of backup files
)
```

### Adding Custom Detection Rules
Add new detection methods in the `NetworkMonitor` class:
```python
def detect_threats(self, ip):
    # Example: Add custom detection rule
    if some_condition:
        self.alert("Custom alert message")
```

### Log Format Customization
Modify the log format:
```python
# In setup_logging method
logging.Formatter('%(asctime)s - %(message)s')  # Change log format
```

### Display Customization
Modify packet display format:
```python
def display_packet_info(self, src_ip, dst_ip, protocol, port):
    # Customize how packets are displayed in console
    print(f"Custom format: {src_ip} -> {dst_ip}")
```

---

## Limitations

- Basic IDS capabilities only
- No deep packet inspection
- No protocol-specific analysis
- Limited to IP-based traffic
- No encrypted traffic analysis

---

## Contributing

Contributions are welcome! Feel free to fork the repository and use it for your own purposes.

---

## Disclaimer

This tool is provided as-is without any warranties. Users are responsible for ensuring they have appropriate permissions before monitoring network traffic.
