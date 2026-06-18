"""
Stage 3: Multiple Threat Detectors
Added port scan detection, suspicious DNS detection, ICMP flood detection, 
and unauthorized device detection. The system can now detect multiple types of attacks.
"""
import sys
import time
import warnings
from collections import defaultdict, deque

try:
    from scapy.all import conf, sniff, IP, ARP, TCP, UDP, DNS, DNSQR, ICMP
except ImportError as exc:
    raise ImportError("Scapy is required.") from exc


class ArpSpoofDetector:
    """Detects ARP spoofing by tracking IP to MAC address mappings"""
    
    def __init__(self):
        self.arp_table = {}
    
    def check(self, packet):
        if not packet.haslayer(ARP):
            return
        
        arp_layer = packet[ARP]
        source_ip = arp_layer.psrc
        source_mac = arp_layer.hwsrc
        previous_mac = self.arp_table.get(source_ip)
        
        if previous_mac and previous_mac != source_mac:
            print(f"\n🚨 ARP SPOOFING: IP {source_ip} changed MAC from {previous_mac} to {source_mac}")
        
        self.arp_table[source_ip] = source_mac


class PortScanDetector:
    """Detects port scanning activity"""
    
    def __init__(self, threshold=15, window=20):
        self.time_window = window
        self.port_threshold = threshold
        self.activity = defaultdict(lambda: deque())
    
    def check(self, packet):
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return
        
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        dest_port = packet[TCP].dport
        timestamp = time.time()
        flow_key = (source_ip, dest_ip)
        
        self.activity[flow_key].append((timestamp, dest_port))
        
        # Clean old entries outside the time window
        while self.activity[flow_key] and timestamp - self.activity[flow_key][0][0] > self.time_window:
            self.activity[flow_key].popleft()
        
        # Check if we've seen too many unique ports
        unique_ports = {port for _, port in self.activity[flow_key]}
        if len(unique_ports) >= self.port_threshold:
            print(f"\n🚨 PORT SCAN: {source_ip} -> {dest_ip} ({len(unique_ports)} unique ports)")
            self.activity[flow_key].clear()


class SuspiciousDnsDetector:
    """Detects suspicious DNS queries"""
    
    SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".online", ".site", ".win", ".pw", ".loan"}
    SUSPICIOUS_KEYWORDS = {"update", "secure", "login", "verify", "bank", "cloud", "wallet", "reset"}
    
    def check(self, packet):
        if not (packet.haslayer(DNS) and packet.haslayer(DNSQR) and 
                packet.haslayer(UDP) and packet.haslayer(IP) and packet[UDP].dport == 53):
            return
        
        source_ip = packet[IP].src
        query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        
        if not query:
            return
        
        if self._is_suspicious(query):
            print(f"\n🚨 SUSPICIOUS DNS: {source_ip} queried {query}")
    
    def _is_suspicious(self, query: str) -> bool:
        normalized = query.lower()
        
        # Check for suspicious TLDs
        if any(normalized.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
            return True
        
        # Check for too many digits (domain generation algorithm)
        if sum(ch.isdigit() for ch in normalized) > 4:
            return True
        
        # Check for suspicious keywords
        if any(keyword in normalized for keyword in self.SUSPICIOUS_KEYWORDS):
            return True
        
        # Check for unusually long domain names
        if len(normalized) > 60:
            return True
        
        return False


class IcmpFloodDetector:
    """Detects ICMP flood attacks"""
    
    def __init__(self):
        self.packet_counts = defaultdict(int)
        self.last_reset = time.time()
    
    def check(self, packet):
        now = time.time()
        
        # Reset counter every 60 seconds
        if now - self.last_reset > 60:
            self.packet_counts.clear()
            self.last_reset = now
        
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            source_ip = packet[IP].src
            self.packet_counts[source_ip] += 1
            
            if self.packet_counts[source_ip] > 50:
                print(f"\n🚨 ICMP FLOOD: {source_ip} sent {self.packet_counts[source_ip]} ICMP packets/min")


class UnauthorizedDeviceDetector:
    """Detects unauthorized devices on the network"""
    
    def __init__(self, allowed_macs=None):
        self.known_macs = set()
        self.allowed_macs = {mac.upper() for mac in allowed_macs} if allowed_macs else set()
    
    def check(self, packet):
        if not packet.haslayer(ARP):
            return
        
        mac_address = packet[ARP].hwsrc.upper()
        
        if mac_address not in self.known_macs:
            self.known_macs.add(mac_address)
            
            # If we have a whitelist and this device isn't on it, alert
            if self.allowed_macs and mac_address not in self.allowed_macs:
                print(f"\n🚨 UNAUTHORIZED DEVICE: {mac_address}")


class NetworkInspector:
    """Orchestrates all threat detectors"""
    
    def __init__(self, allowed_macs=None):
        self.arp_detector = ArpSpoofDetector()
        self.port_scan_detector = PortScanDetector()
        self.dns_detector = SuspiciousDnsDetector()
        self.icmp_detector = IcmpFloodDetector()
        self.device_detector = UnauthorizedDeviceDetector(allowed_macs=allowed_macs)
    
    def inspect(self, packet):
        """Run all detectors on the packet"""
        self.arp_detector.check(packet)
        self.port_scan_detector.check(packet)
        self.dns_detector.check(packet)
        self.icmp_detector.check(packet)
        self.device_detector.check(packet)


def handle_packet(packet, inspector):
    """Process each packet"""
    try:
        inspector.inspect(packet)
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            print(f"Packet: {src} -> {dst}", end="\r")
    except Exception as exc:
        print(f"Error processing packet: {exc}")


def run_packet_capture(interface: str = None, allowed_macs: str = ""):
    """Start packet sniffing with threat detection"""
    
    # Parse allowed MACs if provided
    allowed_macs_set = {mac.strip().upper() for mac in allowed_macs.split(",") if mac.strip()}
    
    inspector = NetworkInspector(allowed_macs=allowed_macs_set)
    
    print(f"Starting IDS on {interface or 'default interface'}...")
    print("Monitoring for: ARP spoofing, port scans, suspicious DNS, ICMP floods, unauthorized devices")
    if allowed_macs_set:
        print(f"Whitelist: {', '.join(allowed_macs_set)}")
    print("Press Ctrl+C to stop.\n")
    
    try:
        sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, inspector), store=False)
    except RuntimeError as exc:
        error_text = str(exc).lower()
        if "layer 2" in error_text or "winpcap" in error_text or "npcap" in error_text:
            print("WinPcap/Npcap unavailable; attempting fallback to layer 3 capture.")
            try:
                l3_socket = conf.L3socket(iface=interface)
                sniff(opened_socket=l3_socket, prn=lambda pkt: handle_packet(pkt, inspector), store=False)
            except OSError as os_exc:
                print(f"Failed to open L3 socket: {os_exc}")
        else:
            raise


if __name__ == "__main__":
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    allowed_macs = sys.argv[2] if len(sys.argv) > 2 else ""
    run_packet_capture(interface, allowed_macs)
