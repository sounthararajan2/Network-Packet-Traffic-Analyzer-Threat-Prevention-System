"""
alerts.py
Handles formatting, printing, and persisting alerts raised by the detection engine.
"""

import csv
import logging
import os
from datetime import datetime

import config


def _setup_file_logger():
    logger = logging.getLogger("netguard")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(config.LOG_FILE)
        fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(fh)
    return logger


_logger = _setup_file_logger()

_SEVERITY_COLORS = {
    "LOW": "\033[93m",      # yellow
    "MEDIUM": "\033[38;5;208m",  # orange
    "HIGH": "\033[91m",     # red
}
_RESET = "\033[0m"


def _ensure_csv_header():
    new_file = not os.path.exists(config.CSV_LOG_FILE)
    if new_file:
        with open(config.CSV_LOG_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "severity", "category", "source_ip", "target", "details"])


def raise_alert(category: str, source_ip: str, target: str, details: str, severity: str = "MEDIUM"):
    """
    Raise an alert: print to console (color-coded), write to log file, append to CSV.
    """
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color = _SEVERITY_COLORS.get(severity, "")
    message = f"[{severity}] {category} | src={source_ip} -> {target} | {details}"

    print(f"{color}{ts} | {message}{_RESET}")

    _logger.info(message)

    _ensure_csv_header()
    with open(config.CSV_LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([ts, severity, category, source_ip, target, details])
