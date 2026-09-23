"""
main.py
NetGuard - Network Packet Traffic Analyzer & Threat Prevention System
Entry point / CLI.

Usage examples:
  sudo python3 main.py --live                     # live capture on default interface
  sudo python3 main.py --live --iface eth0         # live capture on a specific interface
  python3 main.py --pcap sample.pcap               # offline analysis of a pcap file
  sudo python3 main.py --live --count 500          # stop after 500 packets
"""

import argparse
import sys

from capture import PacketCapture
from detectors import DetectionEngine


BANNER = r"""
 _   _      _   _____                     _
| \ | | ___| |_/ ____|_   _  __ _ _ __ __| |
|  \| |/ _ \ __| |  _| | | |/ _` | '__/ _` |
| |\  |  __/ |_| |_| | |_| | (_| | | | (_| |
|_| \_|\___|\__|\____|\__,_|\__,_|_|  \__,_|

Network Packet Traffic Analyzer & Threat Prevention System
Rule-based anomaly detection: port scans, SYN floods, brute-force,
and unusual data transfer volumes.
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="NetGuard - Network Packet Traffic Analyzer & Threat Prevention System"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true", help="Capture live packets from a network interface.")
    mode.add_argument("--pcap", type=str, help="Path to a .pcap file to analyze offline.")

    parser.add_argument("--iface", type=str, default=None,
                         help="Network interface to sniff on (default: scapy's default interface).")
    parser.add_argument("--filter", type=str, default="ip",
                         help="BPF filter expression (default: 'ip'). E.g. 'tcp or udp'.")
    parser.add_argument("--count", type=int, default=0,
                         help="Number of packets to capture in live mode (0 = unlimited, Ctrl+C to stop).")
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()
    engine = DetectionEngine()
    capture = PacketCapture(engine, iface=args.iface, bpf_filter=args.filter)

    try:
        if args.live:
            capture.start_live(packet_count=args.count)
        else:
            capture.analyze_pcap(args.pcap)
    except PermissionError:
        print("\n[!] Permission denied. Live packet capture requires elevated privileges.")
        print("    Try: sudo python3 main.py --live")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
        sys.exit(0)
    except OSError as e:
        print(f"\n[!] Network/interface error: {e}")
        print("    Check that the interface name is correct (see instructions for how to list interfaces).")
        sys.exit(1)


if __name__ == "__main__":
    main()
