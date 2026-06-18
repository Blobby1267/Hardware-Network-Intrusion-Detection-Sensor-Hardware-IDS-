import sys
import os
import warnings
from pathlib import Path

try:
    from scapy.all import conf, sniff, IP, ARP
except ImportError as exc:
    raise ImportError("Scapy is required.") from exc


class ArpSpoofDetector:
    """Detects ARP spoofing by tracking IP to MAC address mappings"""
    
    def __init__(self):
        self.arp_table = {}  # Maps IP addresses to their known MAC addresses
    
    def check(self, packet):
        """Check if packet contains suspicious ARP activity"""
        if not packet.haslayer(ARP):
            return
        
        arp_layer = packet[ARP]
        source_ip = arp_layer.psrc
        source_mac = arp_layer.hwsrc
        
        # Check if we've seen this IP before with a different MAC
        previous_mac = self.arp_table.get(source_ip)
        
        if previous_mac and previous_mac != source_mac:
            print(f"\n!!! ARP SPOOFING DETECTED !!!")
            print(f"IP {source_ip} changed MAC address!")
            print(f"  Previous MAC: {previous_mac}")
            print(f"  Current MAC:  {source_mac}")
            print(f"This could indicate an ARP spoofing attack.\n")
        
        # Update the ARP table
        self.arp_table[source_ip] = source_mac


def handle_packet(packet, detector):
    """Process each packet"""
    try:
        detector.check(packet)
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            print(f"Packet: {src} -> {dst}")
    except Exception as exc:
        print(f"Error processing packet: {exc}")


def run_packet_capture(interface: str = None):
    """Start packet sniffing with ARP spoofing detection"""
    detector = ArpSpoofDetector()
    
    print(f"Starting packet capture with ARP spoofing detection on {interface or 'default interface'}...")
    print("Monitoring for suspicious ARP activity...")
    print("Press Ctrl+C to stop.\n")
    
    try:
        sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, detector), store=False)
    except RuntimeError as exc:
        error_text = str(exc).lower()
        if "layer 2" in error_text or "winpcap" in error_text or "npcap" in error_text:
            print("WinPcap/Npcap unavailable; attempting fallback to layer 3 capture.")
            try:
                l3_socket = conf.L3socket(iface=interface)
                sniff(opened_socket=l3_socket, prn=lambda pkt: handle_packet(pkt, detector), store=False)
            except OSError as os_exc:
                print(f"Failed to open L3 socket: {os_exc}")
                print("On Windows, raw sockets require administrator privileges or Npcap.")
        else:
            raise


if __name__ == "__main__":
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    run_packet_capture(interface)
