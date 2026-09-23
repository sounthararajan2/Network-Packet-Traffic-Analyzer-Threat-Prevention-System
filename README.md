# NetGuard — Network Packet Traffic Analyzer & Threat Prevention System

A Python tool that captures and analyzes live network packets using **rule-based
anomaly detection**, flagging port scans, SYN floods, brute-force connection
attempts, and unusual data transfers in real time.

## What it detects

| Detector | Rule | Default threshold |
|---|---|---|
| **Port Scan** | Single source IP touches many distinct destination ports quickly | ≥15 ports / 10s |
| **SYN Flood** | Single source IP sends abnormal rate of TCP SYN packets | ≥50 SYNs / 10s |
| **Connection Flood / Brute Force** | Single source IP hammers the same destination port (e.g. SSH, RDP) | ≥20 attempts / 10s |
| **Large Data Transfer** | Cumulative bytes between an IP pair exceeds a threshold | ≥50 MB / 60s |

All thresholds are configurable in `config.py`. Alerts are printed to the
console (color-coded by severity), logged to `netguard_alerts.log`, and
appended to `netguard_alerts.csv` for later review/reporting.

## Project structure

```
netguard/
├── main.py                 # CLI entry point
├── capture.py               # Live packet sniffing / pcap replay (scapy)
├── detectors.py              # Rule-based anomaly detection engine
├── alerts.py                 # Alert formatting, console + file + CSV logging
├── config.py                  # All thresholds & settings
├── generate_test_pcap.py       # Creates a synthetic pcap to test detection without live traffic
└── requirements.txt
```

## 1. Requirements

- Python 3.8+
- `scapy` (installed via pip)
- **Live capture** requires:
  - Linux/macOS: root privileges (`sudo`), or `setcap` on the Python binary
  - Windows: [Npcap](https://npcap.com/) installed, and running your terminal as Administrator
- **Offline pcap analysis** requires no special privileges.

## 2. Installation

```bash
# 1. Create the project folder and copy in the files (or unzip the provided archive)
cd netguard

# 2. (Recommended) create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

## 3. Running — Option A: Test it immediately (no root, no live traffic needed)

This generates a synthetic `.pcap` file containing a simulated port scan, SYN
flood, SSH brute-force attempt, and a large data transfer, then replays it
through the detection engine:

```bash
python3 generate_test_pcap.py
python3 main.py --pcap sample.pcap
```

You should see color-coded alerts printed for each attack pattern, and files
`netguard_alerts.log` / `netguard_alerts.csv` created with the same records.

## 4. Running — Option B: Live capture on your machine

**Find your network interface name first:**

```bash
# Linux/macOS
ip a            # or: ifconfig
# Common names: eth0, en0, wlan0

# Windows (run in an elevated/Administrator terminal)
python3 -c "from scapy.all import get_if_list; print(get_if_list())"
```

**Start live capture** (requires elevated privileges to read raw packets):

```bash
# Linux/macOS
sudo python3 main.py --live --iface eth0

# Windows (Administrator PowerShell/CMD, with Npcap installed)
python main.py --live --iface "Ethernet"

# Capture on the default interface, unlimited (Ctrl+C to stop)
sudo python3 main.py --live

# Stop automatically after 1000 packets
sudo python3 main.py --live --count 1000

# Only watch TCP/UDP traffic (BPF filter syntax)
sudo python3 main.py --live --filter "tcp or udp"
```

Leave it running and generate some traffic to see it work, e.g. from another
terminal on the same network:

```bash
# Trigger a (harmless, local) port-scan-like alert against your own machine
nmap -p 1-100 <your-own-LAN-IP>
```
(Only scan hosts/networks you own or are authorized to test.)

## 5. Analyzing a pcap captured elsewhere (Wireshark/tcpdump)

If you already have a capture file:

```bash
python3 main.py --pcap /path/to/capture.pcap
```

## 6. Tuning detection sensitivity

Edit `config.py`:

```python
PORT_SCAN_THRESHOLD = 15          # lower = more sensitive
PORT_SCAN_WINDOW = 10             # seconds

SYN_FLOOD_THRESHOLD = 50
SYN_FLOOD_WINDOW = 10

CONN_RATE_THRESHOLD = 20
CONN_RATE_WINDOW = 10

DATA_TRANSFER_BYTES_THRESHOLD = 50 * 1024 * 1024   # 50 MB
DATA_TRANSFER_WINDOW = 60

IP_ALLOWLIST = {"192.168.1.1"}    # never alert on these IPs (e.g. your monitoring/scanner box)
```

## 7. How it works (architecture)

1. **`capture.py`** uses `scapy.sniff()` (live) or `scapy.rdpcap()` (offline)
   to read packets, extracting `src_ip`, `dst_ip`, `dst_port`, packet size,
   and whether it's a TCP SYN.
2. Each packet's metadata is passed to **`detectors.DetectionEngine`**, which
   fans it out to four independent rule-based detectors, each maintaining a
   small **sliding time-window** of recent activity per source IP (or IP pair).
3. When a detector's threshold is crossed within its window, it calls
   **`alerts.raise_alert()`**, which prints a color-coded console line and
   writes the event to both a text log and a CSV file (for later reporting/analysis).
4. State is periodically pruned (`CLEANUP_INTERVAL`) so long-running captures
   don't grow memory unbounded.

## 8. Extending it

- Add a new detector: copy the pattern in `detectors.py` (a class with
  `process()` + `cleanup()`), instantiate it in `DetectionEngine.__init__`,
  and call it from `handle_packet_event()`.
- Add active prevention (e.g. auto-blocking an IP via `iptables`/firewall
  rules) by hooking additional logic into `alerts.raise_alert()` — this is
  left out by default since it requires root and can be disruptive if a rule
  misfires; test thoroughly before enabling automatic blocking.

## Legal/ethical note

Only capture and analyze traffic on networks and systems you own or are
explicitly authorized to monitor. Live packet capture and port-scan testing
against networks you don't control may be illegal in your jurisdiction.
