"""
generate_test_pcap.py
Generates a synthetic sample.pcap containing traffic patterns that should
trigger each detector in detectors.py. Useful for testing NetGuard without
needing live traffic or root privileges (offline analysis mode).

Run:  python3 generate_test_pcap.py
Then: python3 main.py --pcap sample.pcap
"""

from scapy.all import IP, TCP, UDP, wrpcap
import random
import time

packets = []
base_time = time.time()

# --- Pattern 1: Port scan from 10.0.0.5 -> 192.168.1.10 across many ports ---
scanner_ip = "10.0.0.5"
victim_ip = "192.168.1.10"
for i, port in enumerate(range(20, 45)):
    pkt = IP(src=scanner_ip, dst=victim_ip) / TCP(sport=random.randint(1024, 65000), dport=port, flags="S")
    pkt.time = base_time + i * 0.05
    packets.append(pkt)

# --- Pattern 2: SYN flood from 10.0.0.6 -> 192.168.1.10 on port 80 ---
flood_ip = "10.0.0.6"
for i in range(60):
    pkt = IP(src=flood_ip, dst=victim_ip) / TCP(sport=random.randint(1024, 65000), dport=80, flags="S")
    pkt.time = base_time + 5 + i * 0.02
    packets.append(pkt)

# --- Pattern 3: Brute-force SSH attempts from 10.0.0.7 -> 192.168.1.10:22 ---
brute_ip = "10.0.0.7"
for i in range(25):
    pkt = IP(src=brute_ip, dst=victim_ip) / TCP(sport=random.randint(1024, 65000), dport=22, flags="S")
    pkt.time = base_time + 8 + i * 0.1
    packets.append(pkt)

# --- Pattern 4: Large data transfer from 192.168.1.20 -> 8.8.8.8 ---
transfer_src = "192.168.1.20"
transfer_dst = "8.8.8.8"
big_payload = "A" * 1400
for i in range(400):  # ~400 * ~1400 bytes payload ≈ 560KB (scaled down for demo; threshold lowered below)
    pkt = IP(src=transfer_src, dst=transfer_dst) / TCP(sport=443, dport=54000 + i, flags="A") / big_payload
    pkt.time = base_time + 12 + i * 0.01
    packets.append(pkt)

# --- Normal background traffic (should NOT trigger alerts) ---
for i in range(10):
    pkt = IP(src="192.168.1.50", dst="192.168.1.1") / UDP(sport=53000 + i, dport=53)
    pkt.time = base_time + 20 + i * 0.5
    packets.append(pkt)

wrpcap("sample.pcap", packets)
print(f"[*] Wrote {len(packets)} packets to sample.pcap")
print("[*] Includes: port scan, SYN flood, SSH brute force, large transfer, and normal traffic.")
print("[!] Note: to see the LARGE_DATA_TRANSFER alert with default config.py thresholds (50MB),")
print("    either lower DATA_TRANSFER_BYTES_THRESHOLD in config.py for this test, or increase the loop count above.")
