from prometheus_client import Gauge, Counter, Enum

# --- Metric Definitions ---

# Counters
SHOT_COUNT = Gauge('tmscada_shot_count_total', 'Total number of shots', ['machine'])
BAD_SHOT_COUNT = Gauge('tmscada_bad_shot_count_total', 'Total number of inferior/bad shots', ['machine'])

# Gauges - Times
CYCLE_TIME = Gauge('tmscada_cycle_time_seconds', 'Last cycle time', ['machine'])
INJECT_TIME = Gauge('tmscada_inject_time_seconds', 'Injection time', ['machine'])
CHARGE_TIME = Gauge('tmscada_charge_time_seconds', 'Charge time', ['machine'])

# Gauges - Temperatures
# Labels: machine, zone (1-9, Oil), type (Current/Set)
TEMP_CELSIUS = Gauge('tmscada_temperature_celsius', 'Zone Temperature', ['machine', 'zone', 'type'])

# Gauges - Energy
ENERGY_TOTAL = Gauge('tmscada_energy_consumption_total', 'Total Energy Consumption', ['machine'])

# Enum/State
MACHINE_STATE = Gauge('tmscada_machine_state', 'Operational State Code', ['machine'])
ERROR_STATE = Gauge('tmscada_error_state', 'Current Error Code (0 = Normal)', ['machine'])

def update_metric(machine_ip, key, value):
    """
    Maps internal data_store keys to Prometheus metrics.
    """
    try:
        # --- Temperature Maps ---
        if key.startswith('tmTemp'):
            # Format: tmTemp{i}_Current or tmTemp{i}_Set
            if 'Oil' in key:
                zone = 'Oil'
                m_type = 'Current' # Oil usually doesn't have Set in this map
            elif 'CurrentB' in key:
                 # tmTemp{i}_CurrentB -> Zone {i} Side B
                 parts = key.replace('tmTemp', '').split('_')
                 zone = f"{parts[0]}_B"
                 m_type = 'Current'
            elif 'SetB' in key:
                 parts = key.replace('tmTemp', '').split('_')
                 zone = f"{parts[0]}_B"
                 m_type = 'Set'
            else:
                # tmTemp1_Current -> Zone 1, Current
                parts = key.replace('tmTemp', '').split('_')
                zone = parts[0]
                m_type = parts[1]
            
            TEMP_CELSIUS.labels(machine=machine_ip, zone=zone, type=m_type).set(value)

        # --- Production Stats ---
        elif key == 'ulShotCount' or key == 'dwShotCountCurrent':
            SHOT_COUNT.labels(machine=machine_ip).set(value)
        elif key == 'tmCycletime':
            CYCLE_TIME.labels(machine=machine_ip).set(value / 1000.0 if value > 100 else value) # Assuming ms?
        elif key == 'tmInjecttime':
            INJECT_TIME.labels(machine=machine_ip).set(value / 1000.0 if value > 100 else value)
        elif key == 'tmChargeTime':
            CHARGE_TIME.labels(machine=machine_ip).set(value / 1000.0 if value > 100 else value)
        elif key == 'tmInferior' or key == 'wtmBadShotCount':
            BAD_SHOT_COUNT.labels(machine=machine_ip).set(value)

        # --- Energy ---
        elif key == 'tmTotalEnergyConsumption' or key == 'dwTotalElectricity':
            ENERGY_TOTAL.labels(machine=machine_ip).set(value)

        # --- Status ---
        elif key == 'wOperState':
            MACHINE_STATE.labels(machine=machine_ip).set(value)
        elif key == 'LastError_Code':
            ERROR_STATE.labels(machine=machine_ip).set(value)

    except Exception as e:
        # Fail silently to avoid spamming logs for every minor update
        pass
