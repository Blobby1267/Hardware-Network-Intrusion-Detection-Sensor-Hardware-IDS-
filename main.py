import sys
import time
import warnings
import os
from collections import defaultdict, deque

try:
    from scapy.all import conf, sniff, IP, ARP, TCP, UDP, DNS, DNSQR, ICMP
except ImportError as exc:
    raise ImportError("Scapy is required.") from exc

# Optional hardware support
try:
    from luma.core.interface.serial import i2c
    from luma.oled.device import ssd1306
    from PIL import Image, ImageDraw, ImageFont
    OLED_AVAILABLE = True
except ImportError:
    OLED_AVAILABLE = False

Buzzer = None
LED = None
GPIO_AVAILABLE = False
if sys.platform.startswith("linux") and os.path.exists("/proc/cpuinfo"):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from gpiozero import Buzzer, LED
        GPIO_AVAILABLE = True
    except (ImportError, RuntimeError):
        GPIO_AVAILABLE = False

LED_PIN_MAP = {"green": 17, "yellow": 27, "red": 22}
BUZZER_PIN = 18


class OLEDDisplay:
    """Controls a 128x64 OLED display via I2C"""
    
    def __init__(self):
        self.device = None
        if OLED_AVAILABLE:
            try:
                serial = i2c(port=1, address=0x3C)
                self.device = ssd1306(serial)
                self.font = ImageFont.load_default()
            except Exception:
                self.device = None
    
    def show(self, lines):
        """Display up to 6 lines of text on the OLED"""
        if not self.device:
            return
        
        image = Image.new("1", self.device.size)
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, self.device.width, self.device.height), outline=0, fill=0)
        
        for index, line in enumerate(lines[:6]):
            draw.text((0, index * 10), line, font=self.font, fill=255)
        
        self.device.display(image)


class LEDController:
    """Controls RGB status LEDs"""
    
    def __init__(self):
        self.leds = {}
        if GPIO_AVAILABLE:
            try:
                self.leds = {name: LED(pin) for name, pin in LED_PIN_MAP.items()}
            except Exception:
                self.leds = {}
    
    def update(self, severity: str):
        """Update LED based on severity level"""
        if not self.leds:
            return
        
        # Turn off all LEDs first
        for led in self.leds.values():
            led.off()
        
        # Light up appropriate LED
        if severity == "critical":
            self.leds["red"].on()
        elif severity == "warning":
            self.leds["yellow"].on()
        else:
            self.leds["green"].on()


class BuzzerController:
    """Controls audio buzzer for alerts"""
    
    def __init__(self):
        self.buzzer = None
        if GPIO_AVAILABLE:
            try:
                self.buzzer = Buzzer(BUZZER_PIN)
            except Exception:
                self.buzzer = None
    
    def buzz(self, duration: float = 0.15):
        """Sound the buzzer for the specified duration"""
        if not self.buzzer:
            return
        
        try:
            self.buzzer.on()
            time.sleep(duration)
        finally:
            self.buzzer.off()


class HardwareController:
    """Coordinates all hardware devices"""
    
    def __init__(self):
        self.display = OLEDDisplay()
        self.status_lights = LEDController()
        self.buzzer = BuzzerController()
    
    def update(self, event_type: str, source: str, details: str, severity: str):
        """Update all hardware with new alert information"""
        
        # Update OLED display
        if self.display.device:
            self.display.show([
                f"{severity.upper()} {event_type}",
                f"Source: {source}",
                details[:28],
            ])
        
        # Update LED status
        self.status_lights.update(severity)
        
        # Sound buzzer for critical alerts
        if severity == "critical":
            self.buzzer.buzz(0.25)


# Threat detectors (from stage 3)
class ArpSpoofDetector:
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
            return {
                "type": "ARP Spoofing",
                "source": source_ip,
                "details": f"MAC changed from {previous_mac} to {source_mac}",
                "severity": "critical"
            }
        
        self.arp_table[source_ip] = source_mac
        return None


class PortScanDetector:
    def __init__(self, threshold=15, window=20):
        self.time_window = window
        self.port_threshold = threshold
        self.activity = defaultdict(lambda: deque())
    
    def check(self, packet):
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return None
        
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        dest_port = packet[TCP].dport
        timestamp = time.time()
        flow_key = (source_ip, dest_ip)
        
        self.activity[flow_key].append((timestamp, dest_port))
        
        while self.activity[flow_key] and timestamp - self.activity[flow_key][0][0] > self.time_window:
            self.activity[flow_key].popleft()
        
        unique_ports = {port for _, port in self.activity[flow_key]}
        if len(unique_ports) >= self.port_threshold:
            result = {
                "type": "Port Scan",
                "source": source_ip,
                "details": f"Port scan: {len(unique_ports)} unique ports to {dest_ip}",
                "severity": "warning"
            }
            self.activity[flow_key].clear()
            return result
        
        return None


class SuspiciousDnsDetector:
    SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".online", ".site", ".win", ".pw", ".loan"}
    SUSPICIOUS_KEYWORDS = {"update", "secure", "login", "verify", "bank", "cloud", "wallet", "reset"}
    
    def check(self, packet):
        if not (packet.haslayer(DNS) and packet.haslayer(DNSQR) and 
                packet.haslayer(UDP) and packet.haslayer(IP) and packet[UDP].dport == 53):
            return None
        
        source_ip = packet[IP].src
        query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        
        if not query:
            return None
        
        if self._is_suspicious(query):
            return {
                "type": "Suspicious DNS",
                "source": source_ip,
                "details": f"Suspicious query: {query}",
                "severity": "warning"
            }
        
        return None
    
    def _is_suspicious(self, query: str) -> bool:
        normalized = query.lower()
        
        if any(normalized.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
            return True
        if sum(ch.isdigit() for ch in normalized) > 4:
            return True
        if any(keyword in normalized for keyword in self.SUSPICIOUS_KEYWORDS):
            return True
        if len(normalized) > 60:
            return True
        
        return False


class IcmpFloodDetector:
    def __init__(self):
        self.packet_counts = defaultdict(int)
        self.last_reset = time.time()
    
    def check(self, packet):
        now = time.time()
        
        if now - self.last_reset > 60:
            self.packet_counts.clear()
            self.last_reset = now
        
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            source_ip = packet[IP].src
            self.packet_counts[source_ip] += 1
            
            if self.packet_counts[source_ip] > 50:
                return {
                    "type": "ICMP Flood",
                    "source": source_ip,
                    "details": f"ICMP packets/min: {self.packet_counts[source_ip]}",
                    "severity": "warning"
                }
        
        return None


class UnauthorizedDeviceDetector:
    def __init__(self, allowed_macs=None):
        self.known_macs = set()
        self.allowed_macs = {mac.upper() for mac in allowed_macs} if allowed_macs else set()
    
    def check(self, packet):
        if not packet.haslayer(ARP):
            return None
        
        mac_address = packet[ARP].hwsrc.upper()
        
        if mac_address not in self.known_macs:
            self.known_macs.add(mac_address)
            
            if self.allowed_macs and mac_address not in self.allowed_macs:
                return {
                    "type": "Unauthorized Device",
                    "source": mac_address,
                    "details": f"Unknown device: {mac_address}",
                    "severity": "critical"
                }
        
        return None


class NetworkInspector:
    def __init__(self, allowed_macs=None):
        self.arp_detector = ArpSpoofDetector()
        self.port_scan_detector = PortScanDetector()
        self.dns_detector = SuspiciousDnsDetector()
        self.icmp_detector = IcmpFloodDetector()
        self.device_detector = UnauthorizedDeviceDetector(allowed_macs=allowed_macs)
    
    def inspect(self, packet):
        """Run all detectors and return any alerts"""
        alerts = []
        
        if alert := self.arp_detector.check(packet):
            alerts.append(alert)
        if alert := self.port_scan_detector.check(packet):
            alerts.append(alert)
        if alert := self.dns_detector.check(packet):
            alerts.append(alert)
        if alert := self.icmp_detector.check(packet):
            alerts.append(alert)
        if alert := self.device_detector.check(packet):
            alerts.append(alert)
        
        return alerts


# Global state
hardware_controller = HardwareController()
network_inspector = None


def handle_packet(packet):
    """Process each packet and trigger hardware alerts"""
    try:
        alerts = network_inspector.inspect(packet)
        for alert in alerts:
            print(f"\n🚨 {alert['type']}: {alert['source']} - {alert['details']}")
            hardware_controller.update(
                alert["type"],
                alert["source"],
                alert["details"],
                alert["severity"]
            )
    except Exception as exc:
        print(f"Error processing packet: {exc}")


def run_packet_capture(interface: str = None, allowed_macs: str = ""):
    """Start packet sniffing with threat detection and hardware feedback"""
    
    global network_inspector
    
    allowed_macs_set = {mac.strip().upper() for mac in allowed_macs.split(",") if mac.strip()}
    network_inspector = NetworkInspector(allowed_macs=allowed_macs_set)
    
    print(f"Starting IDS with Hardware Support on {interface or 'default interface'}...")
    print(f"Hardware Status - OLED: {OLED_AVAILABLE}, GPIO: {GPIO_AVAILABLE}")
    print("Press Ctrl+C to stop.\n")
    
    try:
        sniff(iface=interface, prn=handle_packet, store=False)
    except RuntimeError as exc:
        error_text = str(exc).lower()
        if "layer 2" in error_text or "winpcap" in error_text or "npcap" in error_text:
            print("Attempting layer 3 fallback...")
            try:
                l3_socket = conf.L3socket(iface=interface)
                sniff(opened_socket=l3_socket, prn=handle_packet, store=False)
            except OSError as os_exc:
                print(f"Failed: {os_exc}")
        else:
            raise


if __name__ == "__main__":
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    allowed_macs = sys.argv[2] if len(sys.argv) > 2 else ""
    run_packet_capture(interface, allowed_macs)
