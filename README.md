# Hardware Network Intrusion Detection Sensor (Hardware IDS)

A hardware-based Network Intrusion Detection Sensor is a compact monitoring appliance that passively observes network traffic and looks for malicious activity or abnormal behaviour. Unlike a firewall, which actively blocks traffic, an IDS inspects mirrored traffic without interfering with the network.

This project centers on a Raspberry Pi 5 connected to a managed switch configured with a mirror (SPAN) port. The switch duplicates network traffic and sends a copy to the Pi, allowing the IDS to analyse all packets in real time.

## Overview

- Passive network monitoring appliance
- Uses a Raspberry Pi 5 as the core processing unit
- Relies on packet capture and analysis tools such as Scapy or Zeek
- Detects attacks like port scans, ARP spoofing, and suspicious DNS activity
- Stores events in a database and presents them on a local dashboard

## Key Capabilities

- Detect port scans by identifying one source IP rapidly accessing many ports
- Detect ARP spoofing through inconsistent IP-to-MAC bindings
- Analyse DNS requests for suspicious or newly registered domains
- Provide live status updates via onboard display and LEDs
- Generate audible alerts for high-severity detections

## Software Components

- Packet capture and inspection engine
- Threat-detection logic for common attack patterns
- Event storage backend (database or local logs)
- Dashboard for viewing alerts and system status

## Hardware Components

### Core Processing Unit
- **Raspberry Pi 5**
  - Runs the packet capture, analysis software, and local dashboard
- **MicroSD card (32–128 GB, high endurance recommended)**
  - Stores OS, logs, and IDS software
- **Official or high-quality USB-C power supply (5V / 5A recommended)**
  - Ensures stable performance under continuous network load

### Network Capture Hardware
- **Managed Ethernet switch with port mirroring (SPAN) support**
  - Required so the IDS can receive a copy of all network traffic
- **Ethernet cables (Cat6 or better)**
  - Connects router, switch, and IDS device
- **USB 3.0 to Gigabit Ethernet adapter (optional but recommended)**
  - Provides separate interfaces for mirrored traffic and management/dashboard access

### Monitoring & Output Components
- **0.96" or 1.3" I2C OLED display**
  - Shows live stats such as active connections, alerts, bandwidth usage, and system status
- **LEDs (red, yellow, green)**
  - Visual security indicators:
    - Green = normal traffic
    - Yellow = suspicious behaviour
    - Red = confirmed threat
- **Resistors (220Ω–330Ω)**
  - Required for safe LED operation
- **Active buzzer or piezo speaker**
  - Provides audible alerts for high-severity detections

### Optional Sensors / Enhancements
- **Temperature sensor (e.g., DS18B20 or similar)**
  - Monitors device overheating during continuous packet processing
- **Small cooling fan + heatsinks**
  - Recommended for Raspberry Pi 5 to prevent thermal throttling

### Enclosure & Physical Build
- **Raspberry Pi case (preferably with ventilation or fan support)**
  - Protects components and improves airflow
- **Breadboard or prototyping PCB**
  - For clean connections between LEDs, buzzer, and sensors
- **Jumper wires (male-to-female / female-to-female)**
  - Required for GPIO connections

### Optional Expansion Hardware (Advanced Builds)
- **Power over Ethernet (PoE) HAT**
  - Allows the IDS device to be powered from Ethernet when using a PoE switch
- **RTC (Real-Time Clock) module**
  - Keeps accurate timestamps if the device loses internet or power

## Why This Project?

The IDS acts like a security camera for the network: it does not block traffic, but it provides visibility into what is happening and helps administrators respond quickly. This approach is used by enterprise systems such as Suricata, which monitor corporate networks in real time.
