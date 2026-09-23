"""
capture.py
Live packet capture using scapy. Extracts relevant metadata from each packet
and forwards it to the DetectionEngine. Also supports reading from a .pcap
file for offline analysis / testing without root privileges or a live NIC.
"""

import time

from scapy.all import sniff, rdpcap, IP, TCP, UDP

from detectors import DetectionEngine


class PacketCapture:
    def __init__(self, engine: DetectionEngine, iface: str = None, bpf_filter: str = "ip"):
        self.engine = engine
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._packet_count = 0

    def _extract_event(self, pkt):
        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        event = {
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "size_bytes": len(pkt),
            "timestamp": float(pkt.time) if hasattr(pkt, "time") else time.time(),
            "is_syn": False,
            "dst_port": None,
        }

        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            event["dst_port"] = int(tcp_layer.dport)
            # SYN set, ACK not set => new connection attempt
            flags = tcp_layer.flags
            event["is_syn"] = bool(flags & 0x02) and not bool(flags & 0x10)
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            event["dst_port"] = int(udp_layer.dport)

        return event

    def _on_packet(self, pkt):
        self._packet_count += 1
        event = self._extract_event(pkt)
        if event:
            self.engine.handle_packet_event(event)

    def start_live(self, packet_count: int = 0):
        """
        Start live sniffing. packet_count=0 means capture indefinitely (Ctrl+C to stop).
        Requires root/administrator privileges and a supported interface.
        """
        print(f"[*] Starting live capture on interface={self.iface or 'default'} "
              f"filter='{self.bpf_filter}' ... (Ctrl+C to stop)")
        sniff(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=self._on_packet,
            store=False,
            count=packet_count,
        )
        print(f"[*] Capture stopped. Total packets processed: {self._packet_count}")

    def analyze_pcap(self, pcap_path: str):
        """
        Offline mode: replay a saved .pcap file through the same detection engine.
        Useful for testing rules or analysing captures made elsewhere (e.g. tcpdump).
        """
        print(f"[*] Reading pcap file: {pcap_path}")
        packets = rdpcap(pcap_path)
        for pkt in packets:
            self._on_packet(pkt)
        print(f"[*] Analysis complete. Total packets processed: {self._packet_count}")
