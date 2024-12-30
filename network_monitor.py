import scapy.all as scapy
from datetime import datetime
import time
from collections import defaultdict
import argparse
import sys
import os
import platform
import logging
from logging.handlers import RotatingFileHandler

class NetworkMonitor:
    def __init__(self, log_dir="logs"):
        self.ip_connections = defaultdict(int)
        self.ip_ports = defaultdict(set)
        self.suspicious_ips = set()
        
        # Configurable thresholds
        self.CONNECTION_THRESHOLD = 50
        self.PORT_SCAN_THRESHOLD = 10
        
        # Determine OS
        self.platform = platform.system().lower()
        
        # Setup logging
        self.setup_logging(log_dir)
        
    def setup_logging(self, log_dir):
        """Setup logging configuration"""
        # Create logs directory if it doesn't exist
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Setup traffic logger
        self.traffic_logger = logging.getLogger('traffic')
        self.traffic_logger.setLevel(logging.INFO)
        
        traffic_handler = RotatingFileHandler(
            os.path.join(log_dir, 'traffic.log'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        traffic_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(message)s')
        )
        self.traffic_logger.addHandler(traffic_handler)
        
        # Setup security logger
        self.security_logger = logging.getLogger('security')
        self.security_logger.setLevel(logging.WARNING)
        
        security_handler = RotatingFileHandler(
            os.path.join(log_dir, 'security_alerts.log'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        security_handler.setFormatter(
            logging.Formatter('%(asctime)s - ALERT - %(message)s')
        )
        self.security_logger.addHandler(security_handler)
        
    def process_packet(self, packet):
        """Process and analyze network packets"""
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            
            # Update connection tracking
            self.ip_connections[src_ip] += 1
            
            # Track ports for TCP and UDP
            if packet.haslayer(scapy.TCP):
                self.ip_ports[src_ip].add(packet[scapy.TCP].dport)
                protocol = "TCP"
                port = packet[scapy.TCP].dport
            elif packet.haslayer(scapy.UDP):
                self.ip_ports[src_ip].add(packet[scapy.UDP].dport)
                protocol = "UDP"
                port = packet[scapy.UDP].dport
            else:
                protocol = "Other"
                port = None
            
            # Log packet information
            self.log_packet(src_ip, dst_ip, protocol, port)
            
            # Check for threats
            self.detect_threats(src_ip)
            
            # Display packet information
            self.display_packet_info(src_ip, dst_ip, protocol, port)
    
    def log_packet(self, src_ip, dst_ip, protocol, port):
        """Log packet information to file"""
        log_message = f"Source: {src_ip} | Destination: {dst_ip} | Protocol: {protocol}"
        if port:
            log_message += f" | Port: {port}"
        self.traffic_logger.info(log_message)
    
    def detect_threats(self, ip):
        """Detect suspicious network activity"""
        # Check for connection flood
        if self.ip_connections[ip] > self.CONNECTION_THRESHOLD and ip not in self.suspicious_ips:
            alert_msg = f"High connection rate from {ip} (Total: {self.ip_connections[ip]})"
            self.alert(alert_msg)
            self.suspicious_ips.add(ip)
        
        # Check for port scanning
        if len(self.ip_ports[ip]) > self.PORT_SCAN_THRESHOLD and ip not in self.suspicious_ips:
            alert_msg = f"Port scan detected from {ip} (Ports: {len(self.ip_ports[ip])})"
            self.alert(alert_msg)
            self.suspicious_ips.add(ip)
    
    def display_packet_info(self, src_ip, dst_ip, protocol, port):
        """Display packet information in console"""
        current_time = datetime.now().strftime('%H:%M:%S')
        print("\n" + "="*50)
        print(f"Time: {current_time}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        if port:
            print(f"Port: {port}")
        print("="*50)
    
    def alert(self, message):
        """Log and display security alerts"""
        print("\n" + "!"*50)
        print(f"SECURITY ALERT: {message}")
        print("!"*50)
        self.security_logger.warning(message)

def get_interfaces():
    """Get list of network interfaces based on OS"""
    try:
        if platform.system().lower() == 'windows':
            interfaces = scapy.get_windows_if_list()
            return [(iface['name'], iface['description']) for iface in interfaces]
        else:
            interfaces = scapy.get_if_list()
            return [(iface, iface) for iface in interfaces]
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return []

def check_privileges():
    """Check if script has necessary privileges"""
    try:
        if platform.system().lower() == 'windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def main():
    # Check privileges
    if not check_privileges():
        print("Error: This script requires administrator/root privileges!")
        print("Windows: Run Command Prompt as Administrator")
        print("Linux: Run with sudo")
        sys.exit(1)

    # Parse arguments
    parser = argparse.ArgumentParser(description='Cross-Platform Network Monitor')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-l', '--list', action='store_true', help='List available interfaces')
    parser.add_argument('--log-dir', default='logs', help='Directory to store log files')
    args = parser.parse_args()

    # List interfaces if requested
    if args.list:
        print("\nAvailable Network Interfaces:")
        interfaces = get_interfaces()
        for idx, (name, description) in enumerate(interfaces):
            print(f"{idx}: {name} - {description}")
        return

    print("\nCross-Platform Network Monitor")
    print(f"Logs will be saved in: {os.path.abspath(args.log_dir)}")
    print("Press Ctrl+C to stop monitoring")
    
    monitor = NetworkMonitor(log_dir=args.log_dir)
    
    try:
        # Start packet capture
        scapy.sniff(iface=args.interface,
                   prn=monitor.process_packet,
                   store=0)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    except Exception as e:
        print(f"\nError: {e}")
        if platform.system().lower() == 'windows':
            print("Make sure Npcap is installed: https://npcap.com/#download")
        print("Try running with administrator/root privileges")

if __name__ == "__main__":
    main()