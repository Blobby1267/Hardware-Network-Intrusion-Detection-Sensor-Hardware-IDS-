import argparse
import os
import sqlite3
import sys
import threading
import time
import warnings
from collections import defaultdict, deque
from pathlib import Path
import datetime

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

from flask import Flask, render_template

try:
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, conf, sniff
except ImportError as exc:
    raise ImportError("Scapy is required.") from exc

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

ROOT_DIR = Path(__file__).resolve().parent
DB_PATH = ROOT_DIR / "ids_events.db"
DEFAULT_NETWORK_INTERFACE = os.environ.get("IDS_INTERFACE")
AUTHORIZED_MACS = {
    mac.strip().upper()
    for mac in os.environ.get("IDS_ALLOWED_MACS", "").split(",")
    if mac.strip()
}
LED_PIN_MAP = {"green": 17, "yellow": 27, "red": 22}
BUZZER_PIN = 18

app = Flask(__name__)


def get_london_timezone():
    """Return Europe/London timezone info, falling back to local tz if necessary."""
    if ZoneInfo is not None:
        try:
            return ZoneInfo("Europe/London")
        except Exception:
            pass

    try:
        import pytz
        return pytz.timezone("Europe/London")
    except Exception:
        return datetime.datetime.now().astimezone().tzinfo


def initialize_database():
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT,
                details TEXT,
                severity TEXT NOT NULL
            )
            """
        )


def get_recent_events(limit: int = 100):
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT timestamp, event_type, source, details, severity FROM events ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = cursor.fetchall()

    return [
        {
            "timestamp": row[0],
            "event_type": row[1],
            "source": row[2],
            "details": row[3],
            "severity": row[4],
        }
        for row in rows
    ]


class StatusTracker:
    def __init__(self):
        self.start_time = time.time()
        self.total_events = 0
        self.severity_counts = defaultdict(int)
        self.unique_sources = set()
        self.last_alert = None

    def add_event(self, event_type: str, source: str, severity: str):
        self.total_events += 1
        self.severity_counts[severity] += 1
        if source:
            self.unique_sources.add(source)
        if severity in {"critical", "warning"}:
            self.last_alert = {
                "timestamp": datetime.datetime.now(get_london_timezone()).strftime("%Y-%m-%d %H:%M:%S %Z"),
                "event_type": event_type,
                "source": source,
                "severity": severity,
            }

    def summary(self):
        return {
            "total_events": self.total_events,
            "critical": self.severity_counts.get("critical", 0),
            "warning": self.severity_counts.get("warning", 0),
            "info": self.severity_counts.get("info", 0),
            "unique_sources": len(self.unique_sources),
            "last_alert": self.last_alert,
            "uptime_seconds": int(time.time() - self.start_time),
        }


class OLEDDisplay:
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
        if not self.device:
            return

        image = Image.new("1", self.device.size)
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, self.device.width, self.device.height), outline=0, fill=0)

        for index, line in enumerate(lines[:6]):
            draw.text((0, index * 10), line, font=self.font, fill=255)

        self.device.display(image)


class LEDController:
    def __init__(self):
        self.leds = {}
        if GPIO_AVAILABLE:
            try:
                self.leds = {name: LED(pin) for name, pin in LED_PIN_MAP.items()}
            except Exception:
                self.leds = {}

    def update(self, severity: str):
        if not self.leds:
            return

        for led in self.leds.values():
            led.off()

        if severity == "critical":
            self.leds["red"].on()
        elif severity == "warning":
            self.leds["yellow"].on()
        else:
            self.leds["green"].on()


class BuzzerController:
    def __init__(self):
        self.buzzer = None
        if GPIO_AVAILABLE:
            try:
                self.buzzer = Buzzer(BUZZER_PIN)
            except Exception:
                self.buzzer = None

    def buzz(self, duration: float = 0.15):
        if not self.buzzer:
            return

        try:
            self.buzzer.on()
            time.sleep(duration)
        finally:
            self.buzzer.off()


class HardwareController:
    def __init__(self):
        self.display = OLEDDisplay()
        self.status_lights = LEDController()
        self.buzzer = BuzzerController()

    def update(self, event_type: str, source: str, details: str, severity: str):
        if self.display.device:
            self.display.show([
                f"{severity.upper()} {event_type}",
                f"Source: {source}",
                details[:28],
            ])
        self.status_lights.update(severity)
        if severity == "critical":
            self.buzzer.buzz(0.25)


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
            detail = f"IP {source_ip} moved from {previous_mac} to {source_mac}"
            record_event("ARP Spoofing", source_ip, detail, "critical")

        self.arp_table[source_ip] = source_mac


class PortScanDetector:
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
        while self.activity[flow_key] and timestamp - self.activity[flow_key][0][0] > self.time_window:
            self.activity[flow_key].popleft()

        unique_ports = {port for _, port in self.activity[flow_key]}
        if len(unique_ports) >= self.port_threshold:
            detail = f"Suspected port scan from {source_ip} to {dest_ip}: {len(unique_ports)} ports"
            record_event("Port Scan", source_ip, detail, "warning")
            self.activity[flow_key].clear()


class SuspiciousDnsDetector:
    SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".online", ".site", ".win", ".pw", ".loan"}
    SUSPICIOUS_KEYWORDS = {"update", "secure", "login", "verify", "bank", "cloud", "wallet", "reset"}

    def check(self, packet):
        if (
            not packet.haslayer(DNS)
            or not packet.haslayer(DNSQR)
            or not packet.haslayer(UDP)
            or not packet.haslayer(IP)
            or packet[UDP].dport != 53
        ):
            return

        source_ip = packet[IP].src
        query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        if not query:
            return

        if self._is_suspicious(query):
            detail = f"Suspicious DNS query from {source_ip}: {query}"
            record_event("Suspicious DNS", source_ip, detail, "warning")

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
                detail = f"High ICMP packet rate from {source_ip}: {self.packet_counts[source_ip]} packets/min"
                record_event("ICMP Flood", source_ip, detail, "warning")


class UnauthorizedDeviceDetector:
    def __init__(self, allowed_macs=None):
        self.known_macs = set()
        self.allowed_macs = {mac.upper() for mac in allowed_macs} if allowed_macs else set()

    def check(self, packet):
        if not packet.haslayer(ARP):
            return

        mac_address = packet[ARP].hwsrc.upper()
        if mac_address not in self.known_macs:
            self.known_macs.add(mac_address)
            if self.allowed_macs and mac_address not in self.allowed_macs:
                detail = f"Unauthorized device discovered: {mac_address}"
                record_event("Unauthorized Device", mac_address, detail, "critical")


class NetworkInspector:
    def __init__(self):
        self.arp_detector = ArpSpoofDetector()
        self.port_scan_detector = PortScanDetector()
        self.dns_detector = SuspiciousDnsDetector()
        self.icmp_detector = IcmpFloodDetector()
        self.device_detector = UnauthorizedDeviceDetector(allowed_macs=AUTHORIZED_MACS)

    def inspect(self, packet):
        self.arp_detector.check(packet)
        self.port_scan_detector.check(packet)
        self.dns_detector.check(packet)
        self.icmp_detector.check(packet)
        self.device_detector.check(packet)


hardware_controller = HardwareController()
status_tracker = StatusTracker()
network_inspector = NetworkInspector()


def record_event(event_type: str, source: str, details: str, severity: str = "info"):
    timestamp = datetime.datetime.now(get_london_timezone()).strftime("%Y-%m-%d %H:%M:%S %Z")
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            "INSERT INTO events (timestamp, event_type, source, details, severity) VALUES (?, ?, ?, ?, ?)",
            (timestamp, event_type, source, details, severity),
        )

    status_tracker.add_event(event_type, source, severity)
    print(f"[{timestamp}] {severity.upper()} {event_type} - {source}: {details}")
    hardware_controller.update(event_type, source, details, severity)


def handle_packet(packet):
    try:
        network_inspector.inspect(packet)
    except Exception as exc:
        print(f"Packet processing error: {exc}")


def run_packet_capture(interface: str = None):
    print(f"Starting packet capture on {interface or 'default interface'}...")
    try:
        sniff(iface=interface, prn=handle_packet, store=False)
    except RuntimeError as exc:
        error_text = str(exc).lower()
        if "layer 2" in error_text or "winpcap" in error_text or "npcap" in error_text:
            print("WinPcap/Npcap unavailable; attempting fallback to layer 3 capture via conf.L3socket.")
            try:
                l3_socket = conf.L3socket(iface=interface)
                sniff(opened_socket=l3_socket, prn=handle_packet, store=False)
            except OSError as os_exc:
                print("Failed to open Windows native L3 raw socket:", os_exc)
                print("On Windows, raw L3 sockets require administrator privileges or Npcap.")
                print("Install Npcap and run this script as Administrator, or run on a Linux/Raspberry Pi environment.")
        else:
            raise


@app.route("/")
def dashboard():
    events = get_recent_events(100)
    summary = status_tracker.summary()
    hardware_status = {
        "oled": bool(hardware_controller.display.device),
        "gpio": GPIO_AVAILABLE,
    }
    return render_template(
        "dashboard.html",
        events=events,
        summary=summary,
        hardware_status=hardware_status,
    )


def run_dashboard():
    app.run(host="0.0.0.0", port=5000, debug=False)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Hardware Network Intrusion Detection Sensor")
    parser.add_argument(
        "--interface",
        help="Capture interface, e.g. eth0",
        default=DEFAULT_NETWORK_INTERFACE,
    )
    parser.add_argument(
        "--allowed-macs",
        help="Comma-separated MAC addresses that are permitted on the network",
        default=os.environ.get("IDS_ALLOWED_MACS", ""),
    )
    return parser.parse_args()


def configure_authorized_macs(mac_list: str):
    global AUTHORIZED_MACS
    AUTHORIZED_MACS.clear()
    AUTHORIZED_MACS.update({mac.strip().upper() for mac in mac_list.split(",") if mac.strip()})
    if hasattr(network_inspector, "device_detector"):
        network_inspector.device_detector.allowed_macs = set(AUTHORIZED_MACS)


def main():
    args = parse_arguments()
    if args.allowed_macs:
        configure_authorized_macs(args.allowed_macs)

    initialize_database()

    sniffer_thread = threading.Thread(target=run_packet_capture, args=(args.interface,), daemon=True)
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)

    sniffer_thread.start()
    dashboard_thread.start()

    print("Hardware IDS is running. Open http://localhost:5000 to view the dashboard.")
    if args.interface:
        print(f"Listening on interface: {args.interface}")
    if AUTHORIZED_MACS:
        print(f"Authorized MAC addresses: {', '.join(AUTHORIZED_MACS)}")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
