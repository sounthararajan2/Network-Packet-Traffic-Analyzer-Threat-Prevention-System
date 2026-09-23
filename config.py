"""
config.py
Central configuration for NetGuard - Network Packet Traffic Analyzer & Threat Prevention System.
Tune these thresholds to your environment.
"""

# ---- Port Scan Detection ----
# If a single source IP contacts >= PORT_SCAN_THRESHOLD distinct destination ports
# on this host within PORT_SCAN_WINDOW seconds, it is flagged as a port scan.
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 10          # seconds

# ---- SYN Flood Detection ----
# If a single source IP sends >= SYN_FLOOD_THRESHOLD SYN packets (no completed handshake)
# within SYN_FLOOD_WINDOW seconds, flag as a possible SYN flood.
SYN_FLOOD_THRESHOLD = 50
SYN_FLOOD_WINDOW = 10          # seconds

# ---- Unusual Data Transfer Detection ----
# If total bytes to/from a single IP pair exceeds this many bytes within the window,
# flag as an unusual/large data transfer.
DATA_TRANSFER_BYTES_THRESHOLD = 50 * 1024 * 1024   # 50 MB
DATA_TRANSFER_WINDOW = 60      # seconds

# ---- Repeated Connection / Brute-force-like Detection ----
# If a source IP opens >= CONN_RATE_THRESHOLD new connections to the SAME destination port
# within CONN_RATE_WINDOW seconds (e.g. hammering SSH/RDP), flag it.
CONN_RATE_THRESHOLD = 20
CONN_RATE_WINDOW = 10          # seconds

# ---- Known sensitive ports worth extra attention (informational tagging only) ----
SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 3306: "MySQL", 5432: "PostgreSQL"}

# ---- Housekeeping ----
CLEANUP_INTERVAL = 30          # seconds, how often stale tracking state is purged
LOG_FILE = "netguard_alerts.log"
CSV_LOG_FILE = "netguard_alerts.csv"

# ---- IP allowlist (never alert on traffic from/to these, e.g. your own scanner, monitoring box) ----
IP_ALLOWLIST = set([
    # "127.0.0.1",
])
