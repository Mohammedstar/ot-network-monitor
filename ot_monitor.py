"""
=============================================================
OT/ICS Network Monitor — Python Security Tool
=============================================================
Author:  Mohammed Satar | OT Cybersecurity Engineer
Version: 1.0

Purpose:
  Monitors industrial network traffic for anomalies.
  Detects unauthorized Modbus/DNP3/EtherNet-IP traffic.
  Generates security alerts per ISA/IEC 62443.
  
Career Stage: OT Cybersecurity Engineer
Relevant to: Industrial Control System (ICS) Security
=============================================================
"""

import socket
import struct
import threading
import time
import json
import csv
import ipaddress
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

# ─── OT Protocol Port Numbers ────────────────────────────
OT_PORTS = {
    502:   "Modbus TCP",
    20000: "DNP3",
    44818: "EtherNet/IP",
    102:   "S7comm (Siemens)",
    2222:  "EtherNet/IP UDP",
    4840:  "OPC-UA",
    18245: "GE-SRTP",
    1089:  "FF HSE",
    9600:  "IEC 60870-5-104",
}

# ─── Known Good Devices (whitelist) ──────────────────────
# In real OT environments, these are configured by the engineer
KNOWN_DEVICES = {
    "192.168.1.10": "PLC-001 (Siemens S7-300)",
    "192.168.1.11": "PLC-002 (Allen Bradley)",
    "192.168.1.20": "SCADA Server",
    "192.168.1.30": "HMI Station 1",
    "192.168.1.31": "HMI Station 2",
    "192.168.1.100": "Engineering Workstation",
}


@dataclass
class SecurityEvent:
    timestamp: str
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str        # UNAUTHORIZED, ANOMALY, SCAN, etc.
    source_ip: str
    dest_ip: str
    port: int
    protocol: str
    description: str
    raw_data: Optional[bytes] = None


@dataclass
class DeviceProfile:
    ip: str
    first_seen: str = ""
    last_seen: str = ""
    protocols: set = field(default_factory=set)
    total_packets: int = 0
    is_whitelisted: bool = False
    is_rogue: bool = False


class ModbusParser:
    """
    Parse Modbus TCP packets to identify function codes.
    Detects unauthorized write operations that could affect
    industrial process control.
    """
    FUNCTION_CODES = {
        0x01: "Read Coils",
        0x02: "Read Discrete Inputs",
        0x03: "Read Holding Registers",
        0x04: "Read Input Registers",
        0x05: "Write Single Coil",        # ← WRITE — monitor carefully
        0x06: "Write Single Register",    # ← WRITE
        0x0F: "Write Multiple Coils",     # ← WRITE MULTIPLE
        0x10: "Write Multiple Registers", # ← WRITE MULTIPLE
        0x17: "Read/Write Multiple Regs", # ← READ + WRITE
        0x2B: "Read Device Identification",
    }
    WRITE_FUNCTION_CODES = {0x05, 0x06, 0x0F, 0x10, 0x17}

    @staticmethod
    def parse(data: bytes) -> Optional[dict]:
        """Parse Modbus TCP Application Data Unit (ADU)."""
        if len(data) < 8:
            return None
        try:
            # Modbus TCP header: Transaction ID (2), Protocol ID (2), Length (2), Unit ID (1)
            transaction_id = struct.unpack(">H", data[0:2])[0]
            protocol_id    = struct.unpack(">H", data[2:4])[0]
            length         = struct.unpack(">H", data[4:6])[0]
            unit_id        = data[6]
            function_code  = data[7]

            if protocol_id != 0:  # Not Modbus
                return None

            result = {
                "transaction_id": transaction_id,
                "unit_id": unit_id,
                "function_code": function_code,
                "function_name": ModbusParser.FUNCTION_CODES.get(function_code, f"Unknown (0x{function_code:02X})"),
                "is_write": function_code in ModbusParser.WRITE_FUNCTION_CODES,
                "is_exception": (function_code & 0x80) != 0,
            }

            # Parse address for write operations
            if function_code in (0x05, 0x06) and len(data) >= 12:
                result["address"] = struct.unpack(">H", data[8:10])[0]
                result["value"]   = struct.unpack(">H", data[10:12])[0]
            elif function_code in (0x0F, 0x10) and len(data) >= 12:
                result["start_address"] = struct.unpack(">H", data[8:10])[0]
                result["quantity"]      = struct.unpack(">H", data[10:12])[0]

            return result
        except (struct.error, IndexError):
            return None


class OTSecurityMonitor:
    """
    Main OT/ICS security monitoring engine.
    
    Monitors network traffic and generates security events
    based on ISA/IEC 62443 security zone policies.
    """

    def __init__(self, interface: str = "0.0.0.0"):
        self.interface = interface
        self.events: deque = deque(maxlen=1000)
        self.devices: dict = {}
        self.packet_count: int = 0
        self.lock = threading.Lock()
        self.running = False
        self.stats = defaultdict(int)

        # Traffic baseline per device (for anomaly detection)
        self.traffic_baseline: dict = defaultdict(lambda: deque(maxlen=60))

        # Alert thresholds
        self.SCAN_THRESHOLD  = 10  # >10 different ports in 60s = likely scan
        self.BURST_THRESHOLD = 100 # >100 packets/sec = anomaly

    def _classify_severity(self, event_type: str, protocol: str, is_write: bool, is_rogue: bool) -> str:
        if is_rogue:
            return "CRITICAL"
        if is_write:
            return "HIGH"
        if event_type == "PORT_SCAN":
            return "HIGH"
        if event_type == "UNAUTHORIZED_PROTOCOL":
            return "MEDIUM"
        return "LOW"

    def analyze_packet(self, src_ip: str, dst_ip: str, dst_port: int, payload: bytes):
        """Analyze a captured packet for security events."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        events_generated = []

        with self.lock:
            # Track device
            if src_ip not in self.devices:
                self.devices[src_ip] = DeviceProfile(
                    ip=src_ip,
                    first_seen=now,
                    last_seen=now,
                    is_whitelisted=(src_ip in KNOWN_DEVICES),
                    is_rogue=(src_ip not in KNOWN_DEVICES)
                )
            dev = self.devices[src_ip]
            dev.last_seen = now
            dev.total_packets += 1

            # ── Check: Rogue (unknown) device communicating on OT port ──
            if dev.is_rogue and dst_port in OT_PORTS:
                event = SecurityEvent(
                    timestamp=now,
                    severity="CRITICAL",
                    category="UNAUTHORIZED_DEVICE",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    port=dst_port,
                    protocol=OT_PORTS.get(dst_port, "Unknown"),
                    description=f"⚠️  UNKNOWN device {src_ip} communicating on "
                                f"{OT_PORTS[dst_port]} (Port {dst_port}). "
                                f"Not in whitelist! Possible rogue device.",
                )
                events_generated.append(event)
                self.stats["critical_events"] += 1

            # ── Modbus Deep Packet Inspection ──────────────────────────
            if dst_port == 502 and len(payload) >= 8:
                modbus = ModbusParser.parse(payload)
                if modbus:
                    dev.protocols.add("Modbus TCP")
                    if modbus["is_write"]:
                        severity = "HIGH" if dev.is_rogue else "MEDIUM"
                        event = SecurityEvent(
                            timestamp=now,
                            severity=severity,
                            category="MODBUS_WRITE",
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            port=502,
                            protocol="Modbus TCP",
                            description=f"Modbus WRITE detected: {modbus['function_name']} "
                                        f"(FC=0x{modbus['function_code']:02X}) "
                                        f"from {src_ip} to {dst_ip}:{dst_port}. "
                                        f"Address: {modbus.get('address', modbus.get('start_address', '?'))}",
                        )
                        events_generated.append(event)
                        self.stats["modbus_writes"] += 1

            # ── Traffic to OT ports by known devices ───────────────────
            if dst_port in OT_PORTS and not dev.is_rogue:
                dev.protocols.add(OT_PORTS[dst_port])
                self.stats["ot_packets"] += 1

            # ── S7comm (Siemens PLC) detection ─────────────────────────
            if dst_port == 102:
                event = SecurityEvent(
                    timestamp=now,
                    severity="INFO",
                    category="S7COMM",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    port=102,
                    protocol="S7comm (Siemens)",
                    description=f"Siemens S7 communication detected: {src_ip} → {dst_ip}",
                )
                events_generated.append(event)

            # Add events to log
            self.events.extend(events_generated)
            self.packet_count += 1
            self.stats["total_packets"] += 1

        return events_generated

    def get_status(self) -> dict:
        """Return current monitoring status."""
        with self.lock:
            return {
                "packet_count":     self.packet_count,
                "devices_seen":     len(self.devices),
                "known_devices":    sum(1 for d in self.devices.values() if d.is_whitelisted),
                "rogue_devices":    sum(1 for d in self.devices.values() if d.is_rogue),
                "total_events":     len(self.events),
                "critical_events":  self.stats["critical_events"],
                "modbus_writes":    self.stats["modbus_writes"],
                "ot_packets":       self.stats["ot_packets"],
                "recent_events":    [
                    {k: v for k, v in vars(e).items() if k != "raw_data"}
                    for e in list(self.events)[-10:]
                ],
            }

    def generate_report(self, output_file: str = "ot_security_report.json"):
        """Generate a security assessment report."""
        with self.lock:
            report = {
                "report_generated": datetime.now().isoformat(),
                "summary": self.get_status(),
                "devices": {
                    ip: {
                        "first_seen": dev.first_seen,
                        "last_seen":  dev.last_seen,
                        "protocols":  list(dev.protocols),
                        "packets":    dev.total_packets,
                        "status":     "WHITELISTED" if dev.is_whitelisted else "ROGUE",
                        "name":       KNOWN_DEVICES.get(ip, "Unknown"),
                    }
                    for ip, dev in self.devices.items()
                },
                "all_events": [
                    {k: v for k, v in vars(e).items() if k != "raw_data"}
                    for e in self.events
                ],
            }

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[OK] Report saved to {output_file}")
        return report


def demo_mode():
    """Run the monitor in demonstration mode with simulated traffic."""
    import random

    monitor = OTSecurityMonitor()

    print("=" * 60)
    print(" OT/ICS Network Security Monitor")
    print(" Author: Mohammed Satar | OT Cybersecurity Engineer")
    print("=" * 60)
    print("[DEMO MODE] Simulating industrial network traffic...")
    print()

    # Simulate various traffic scenarios
    scenarios = [
        # Normal SCADA reads
        ("192.168.1.100", "192.168.1.10", 502, b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0A"),
        ("192.168.1.30",  "192.168.1.10", 502, b"\x00\x02\x00\x00\x00\x06\x01\x01\x00\x10\x00\x05"),
        # Unauthorized write from unknown device!
        ("192.168.5.99",  "192.168.1.10", 502, b"\x00\x03\x00\x00\x00\x06\x01\x06\x00\x64\xFF\xFF"),
        # Rogue device on EtherNet/IP
        ("10.0.0.50",     "192.168.1.11", 44818, b"\x65\x00\x04\x00"),
        # Known HMI normal read
        ("192.168.1.31",  "192.168.1.10", 502, b"\x00\x04\x00\x00\x00\x06\x01\x04\x00\x00\x00\x20"),
        # S7comm communication
        ("192.168.1.100", "192.168.1.10", 102, b"\x03\x00\x00\x16"),
    ]

    for scenario in scenarios:
        src, dst, port, payload = scenario
        events = monitor.analyze_packet(src, dst, port, payload)

        for event in events:
            color = "\033[91m" if event.severity == "CRITICAL" else \
                    "\033[93m" if event.severity == "HIGH" else \
                    "\033[96m" if event.severity == "MEDIUM" else "\033[92m"
            reset = "\033[0m"
            print(f"{color}[{event.severity}]{reset} {event.timestamp}")
            print(f"  Category: {event.category}")
            print(f"  {event.description}")
            print()
        time.sleep(0.5)

    # Print final status
    status = monitor.get_status()
    print("\n" + "=" * 60)
    print(" MONITORING SUMMARY")
    print("=" * 60)
    print(f"  Total Packets Analyzed: {status['packet_count']}")
    print(f"  Devices Seen:           {status['devices_seen']}")
    print(f"  Known (Whitelisted):    {status['known_devices']}")
    print(f"  ROGUE (Unknown!):       {status['rogue_devices']}")
    print(f"  Critical Events:        {status['critical_events']}")
    print(f"  Modbus Write Ops:       {status['modbus_writes']}")
    print()

    # Generate report
    monitor.generate_report("ot_security_report.json")


if __name__ == "__main__":
    demo_mode()
