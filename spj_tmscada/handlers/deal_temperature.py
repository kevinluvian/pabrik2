import struct
import logging
from precision_map import get_divisor

logger = logging.getLogger(__name__)

def deal_temperature(server, client_addr, data):
    """
    Handles PID 0x10002: Temperature Telemetry
    Struct size: 84 bytes (payload)
    """
    logger.info(f"deal_temperature received {len(data)} bytes from {client_addr}")
    payload = data[16:]
    
    if len(payload) < 84:
        logger.warning("deal_temperature payload too short")
        return
        
    shot_count = struct.unpack_from('<I', payload, 0)[0]
    temp_real = struct.unpack_from('<20H', payload, 4)
    temp_set = struct.unpack_from('<20H', payload, 44)
    
    server.data_store['ShotCount'] = shot_count
    
    def parse_negative(val):
        if val == 65535:
            return -1
        return val

    for i in range(9):
        # Current Temps (no division)
        key_real = f'tmTemp{i+1}_Current'
        server.data_store[key_real] = parse_negative(float(temp_real[i]))
        
        # Set Temps (with division)
        key_set = f'tmTemp{i+1}_Set'
        server.data_store[key_set] = parse_negative(temp_set[i] / get_divisor(key_set))
        
        # 'B' side Current
        key_real_b = f'tmTemp{i+1}_CurrentB'
        server.data_store[key_real_b] = parse_negative(float(temp_real[i+10]))
        
        # 'B' side Set
        key_set_b = f'tmTemp{i+1}_SetB'
        server.data_store[key_set_b] = parse_negative(temp_set[i+10] / get_divisor(key_set_b))
        
    # Oil Temp (no division)
    key_oil = 'tmTempOil_Current'
    server.data_store[key_oil] = parse_negative(float(temp_real[9]))
    
    logger.info(f"deal_temperature parsed ShotCount={shot_count} and temps.")

    # No response sent (Silent Handler)
