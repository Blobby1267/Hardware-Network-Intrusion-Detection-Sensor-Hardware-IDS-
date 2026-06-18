import sys
import os
import warnings

try:
    from scapy.all import conf, sniff, IP
except ImportError as exc:
    raise ImportError("Scapy is required.") from exc


def handle_packet(packet):
    """Simple packet handler - just print basic info"""
    try:
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            print(f"Packet: {src} -> {dst} (Protocol: {proto})")
    except Exception as exc:
        print(f"Error processing packet: {exc}")


def run_packet_capture(interface: str = None):
    """Start packet sniffing"""
    print(f"Starting basic packet capture on {interface or 'default interface'}...")
    print("Press Ctrl+C to stop.")
    try:
        sniff(iface=interface, prn=handle_packet, store=False)
    except RuntimeError as exc:
        error_text = str(exc).lower()
        if "layer 2" in error_text or "winpcap" in error_text or "npcap" in error_text:
            print("WinPcap/Npcap unavailable; attempting fallback to layer 3 capture.")
            try:
                l3_socket = conf.L3socket(iface=interface)
                sniff(opened_socket=l3_socket, prn=handle_packet, store=False)
            except OSError as os_exc:
                print(f"Failed to open L3 socket: {os_exc}")
                print("On Windows, raw sockets require administrator privileges or Npcap.")
        else:
            raise


if __name__ == "__main__":
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    run_packet_capture(interface)
