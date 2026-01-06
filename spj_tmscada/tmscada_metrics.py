from prometheus_client import Gauge, Info, Counter
from collections import defaultdict

# --- Metric Definitions ---

# Meta-Metric: Packet Counts (System Metric)
PACKET_COUNT = Counter('tmscada_packets_processed_total', 'Total number of packets processed', ['handler'])

# Unified Numeric Metric
# Exposes ALL numeric values using the original key name as the 'param' label.
# This avoids dynamic metric creation while ensuring exhaustive coverage.
METRIC_VALUE = Gauge('tmscada_metric_value', 'Numeric value of a machine parameter', ['machine', 'param'])

# Unified String/Info Metric
# Exposes ALL string values as labels in this Info metric.
MACHINE_INFO = Info('tmscada_machine_info', 'Machine String Parameters', ['machine'])

# Global cache to accumulate info labels per machine
# Structure: { machine_label: { 'ip_address': '...', 'tmCraftID': '...', ... } }
_machine_info_cache = defaultdict(dict)

def update_metric(machine_label, machine_ip, key, value):
    """
    Exhaustively exposes all parameters to Prometheus using their original keys.
    - Numeric values -> tmscada_metric_value{param="OriginalKey"}
    - String values  -> tmscada_machine_info{OriginalKey="value"}
    """
    try:
        # --- 1. Manage Metadata (IP & Strings) ---
        
        # Always ensure IP is recorded in metadata cache
        if _machine_info_cache[machine_label].get('ip_address') != machine_ip:
            _machine_info_cache[machine_label]['ip_address'] = machine_ip
            # Trigger update to ensure IP is captured immediately
            MACHINE_INFO.labels(machine=machine_label).info(_machine_info_cache[machine_label])

        if isinstance(value, str):
            # Clean string value
            clean_val = value.strip()
            
            # Only update if value changed to avoid excessive mutex locking in Prometheus client
            if _machine_info_cache[machine_label].get(key) != clean_val:
                _machine_info_cache[machine_label][key] = clean_val
                MACHINE_INFO.labels(machine=machine_label).info(_machine_info_cache[machine_label])
            return

        # --- 2. Numeric Values ---
        if isinstance(value, (int, float)):
            # Direct mapping: Original Key -> Param Label
            # This covers ALL numeric parameters (Temps, Pressures, Counts, Energies, etc.)
            METRIC_VALUE.labels(machine=machine_label, param=key).set(value)
            return

    except Exception as e:
        # Fail silently to avoid spamming logs for every minor update issue
        pass
