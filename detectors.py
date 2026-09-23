"""
detectors.py
Rule-based anomaly detection engine.

Each detector keeps a small sliding-window state (per source IP, or per IP pair)
and evaluates simple threshold rules on every packet event it receives.
This is intentionally rule-based (not ML) so behaviour is transparent and auditable.
"""

import threading
import time
from collections import defaultdict, deque

import config
from alerts import raise_alert


class PortScanDetector:
    """
    Flags a source IP as a port-scanner if it touches many distinct destination
    ports within a short time window.
    """

    def __init__(self):
        # src_ip -> deque[(timestamp, dst_port)]
        self._activity = defaultdict(deque)
        self._alerted_recently = {}  # src_ip -> last alert time (avoid alert spam)
        self._lock = threading.Lock()

    def process(self, src_ip, dst_ip, dst_port, timestamp):
        if src_ip in config.IP_ALLOWLIST:
            return
        with self._lock:
            dq = self._activity[src_ip]
            dq.append((timestamp, dst_port))

            # Drop entries outside the window
            cutoff = timestamp - config.PORT_SCAN_WINDOW
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            distinct_ports = {p for _, p in dq}

            if len(distinct_ports) >= config.PORT_SCAN_THRESHOLD:
                last_alert = self._alerted_recently.get(src_ip, 0)
                if timestamp - last_alert > config.PORT_SCAN_WINDOW:
                    self._alerted_recently[src_ip] = timestamp
                    raise_alert(
                        category="PORT_SCAN",
                        source_ip=src_ip,
                        target=dst_ip,
                        details=(
                            f"{len(distinct_ports)} distinct ports contacted in "
                            f"{config.PORT_SCAN_WINDOW}s (threshold={config.PORT_SCAN_THRESHOLD})"
                        ),
                        severity="HIGH",
                    )

    def cleanup(self, now):
        with self._lock:
            cutoff = now - config.PORT_SCAN_WINDOW
            for src_ip in list(self._activity.keys()):
                dq = self._activity[src_ip]
                while dq and dq[0][0] < cutoff:
                    dq.popleft()
                if not dq:
                    del self._activity[src_ip]


class SynFloodDetector:
    """
    Flags a source IP sending an abnormally high rate of TCP SYN packets
    (classic precursor to SYN flood / DoS or aggressive scanning).
    """

    def __init__(self):
        self._syn_times = defaultdict(deque)  # src_ip -> deque[timestamp]
        self._alerted_recently = {}
        self._lock = threading.Lock()

    def process(self, src_ip, dst_ip, timestamp):
        if src_ip in config.IP_ALLOWLIST:
            return
        with self._lock:
            dq = self._syn_times[src_ip]
            dq.append(timestamp)
            cutoff = timestamp - config.SYN_FLOOD_WINDOW
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= config.SYN_FLOOD_THRESHOLD:
                last_alert = self._alerted_recently.get(src_ip, 0)
                if timestamp - last_alert > config.SYN_FLOOD_WINDOW:
                    self._alerted_recently[src_ip] = timestamp
                    raise_alert(
                        category="SYN_FLOOD",
                        source_ip=src_ip,
                        target=dst_ip,
                        details=(
                            f"{len(dq)} SYN packets in {config.SYN_FLOOD_WINDOW}s "
                            f"(threshold={config.SYN_FLOOD_THRESHOLD})"
                        ),
                        severity="HIGH",
                    )

    def cleanup(self, now):
        with self._lock:
            cutoff = now - config.SYN_FLOOD_WINDOW
            for src_ip in list(self._syn_times.keys()):
                dq = self._syn_times[src_ip]
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if not dq:
                    del self._syn_times[src_ip]


class DataTransferDetector:
    """
    Flags unusually large cumulative data transfer between an IP pair within
    a time window (possible exfiltration or large unauthorized download/upload).
    """

    def __init__(self):
        # (src_ip, dst_ip) -> deque[(timestamp, size_bytes)]
        self._transfers = defaultdict(deque)
        self._alerted_recently = {}
        self._lock = threading.Lock()

    def process(self, src_ip, dst_ip, size_bytes, timestamp):
        if src_ip in config.IP_ALLOWLIST or dst_ip in config.IP_ALLOWLIST:
            return
        key = (src_ip, dst_ip)
        with self._lock:
            dq = self._transfers[key]
            dq.append((timestamp, size_bytes))
            cutoff = timestamp - config.DATA_TRANSFER_WINDOW
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            total_bytes = sum(sz for _, sz in dq)

            if total_bytes >= config.DATA_TRANSFER_BYTES_THRESHOLD:
                last_alert = self._alerted_recently.get(key, 0)
                if timestamp - last_alert > config.DATA_TRANSFER_WINDOW:
                    self._alerted_recently[key] = timestamp
                    mb = total_bytes / (1024 * 1024)
                    raise_alert(
                        category="LARGE_DATA_TRANSFER",
                        source_ip=src_ip,
                        target=dst_ip,
                        details=(
                            f"{mb:.2f} MB transferred in {config.DATA_TRANSFER_WINDOW}s "
                            f"(threshold={config.DATA_TRANSFER_BYTES_THRESHOLD / (1024*1024):.0f} MB)"
                        ),
                        severity="MEDIUM",
                    )

    def cleanup(self, now):
        with self._lock:
            cutoff = now - config.DATA_TRANSFER_WINDOW
            for key in list(self._transfers.keys()):
                dq = self._transfers[key]
                while dq and dq[0][0] < cutoff:
                    dq.popleft()
                if not dq:
                    del self._transfers[key]


class ConnectionRateDetector:
    """
    Flags a source IP hammering the SAME destination port with many connection
    attempts in a short window (e.g. brute-force login attempts on SSH/RDP).
    """

    def __init__(self):
        # (src_ip, dst_port) -> deque[timestamp]
        self._attempts = defaultdict(deque)
        self._alerted_recently = {}
        self._lock = threading.Lock()

    def process(self, src_ip, dst_ip, dst_port, timestamp):
        if src_ip in config.IP_ALLOWLIST:
            return
        key = (src_ip, dst_port)
        with self._lock:
            dq = self._attempts[key]
            dq.append(timestamp)
            cutoff = timestamp - config.CONN_RATE_WINDOW
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= config.CONN_RATE_THRESHOLD:
                last_alert = self._alerted_recently.get(key, 0)
                if timestamp - last_alert > config.CONN_RATE_WINDOW:
                    self._alerted_recently[key] = timestamp
                    service = config.SENSITIVE_PORTS.get(dst_port, str(dst_port))
                    raise_alert(
                        category="CONNECTION_FLOOD",
                        source_ip=src_ip,
                        target=f"{dst_ip}:{dst_port} ({service})",
                        details=(
                            f"{len(dq)} connection attempts in {config.CONN_RATE_WINDOW}s "
                            f"(threshold={config.CONN_RATE_THRESHOLD}) - possible brute force"
                        ),
                        severity="HIGH" if dst_port in config.SENSITIVE_PORTS else "MEDIUM",
                    )

    def cleanup(self, now):
        with self._lock:
            cutoff = now - config.CONN_RATE_WINDOW
            for key in list(self._attempts.keys()):
                dq = self._attempts[key]
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if not dq:
                    del self._attempts[key]


class DetectionEngine:
    """
    Aggregates all individual rule-based detectors and dispatches packet
    metadata to each of them. Also runs periodic cleanup to bound memory use.
    """

    def __init__(self):
        self.port_scan = PortScanDetector()
        self.syn_flood = SynFloodDetector()
        self.data_transfer = DataTransferDetector()
        self.conn_rate = ConnectionRateDetector()
        self._last_cleanup = time.time()

    def handle_packet_event(self, event: dict):
        """
        event is a dict with keys (as applicable):
          src_ip, dst_ip, dst_port, size_bytes, is_syn, timestamp
        """
        ts = event.get("timestamp", time.time())
        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        dst_port = event.get("dst_port")
        size_bytes = event.get("size_bytes", 0)
        is_syn = event.get("is_syn", False)

        if src_ip and dst_ip and dst_port is not None:
            self.port_scan.process(src_ip, dst_ip, dst_port, ts)
            self.conn_rate.process(src_ip, dst_ip, dst_port, ts)

        if is_syn and src_ip and dst_ip:
            self.syn_flood.process(src_ip, dst_ip, ts)

        if src_ip and dst_ip and size_bytes:
            self.data_transfer.process(src_ip, dst_ip, size_bytes, ts)

        # Periodic cleanup so long-running captures don't leak memory
        if ts - self._last_cleanup > config.CLEANUP_INTERVAL:
            self.port_scan.cleanup(ts)
            self.syn_flood.cleanup(ts)
            self.data_transfer.cleanup(ts)
            self.conn_rate.cleanup(ts)
            self._last_cleanup = ts
