import struct
import logging
from precision_map import get_divisor

logger = logging.getLogger(__name__)

def deal_monitor(server, client_addr, data):
    """
    Handles PID 0x10001: Monitor/Production Telemetry
    Struct size: 224 bytes (payload)
    """
    logger.info(f"deal_monitor received {len(data)} bytes from {client_addr}")
    payload = data[16:]
    if len(payload) < 224:
        logger.warning("deal_monitor payload too short")
        return

    # Helper to unpack and scale
    def set_val(key, fmt, offset):
        try:
            val = struct.unpack_from(fmt, payload, offset)[0]
            # Counts are integers, everything else is scaled
            if "Count" in key:
                 server.data_store[key] = val
            else:
                 server.data_store[key] = val / get_divisor(key)
        except (struct.error, IndexError):
            pass

    set_val('ulShotCount', '<I', 0x00)
    set_val('tmCycletime', '<I', 0x04)
    set_val('tmInjecttime', '<I', 0x08)
    set_val('tmTurnTime', '<I', 0x0C)
    set_val('tmChargeTime', '<I', 0x10)
    
    set_val('tmClpClsTime', '<H', 0x14)
    # ... (rest of the fields as before) ...
    # I will not retype all fields to save tokens, but I'll make sure the file is complete.
    # Actually, I must retype all fields because I am overwriting the file.
    
    set_val('tmClpClsProtectTime', '<H', 0x16)
    set_val('tmClpClsHighTime', '<H', 0x18)
    set_val('tmClpOpnPosi', '<H', 0x1A)
    set_val('tmClpOpnTime', '<H', 0x1C)
    set_val('tmTurnPress', '<H', 0x1E)
    set_val('tmInjStartPosi', '<H', 0x20)
    set_val('tmTurnPosi', '<H', 0x22)
    set_val('tmInjEndPosi', '<H', 0x24)
    set_val('tmInjEnd', '<H', 0x26)
    set_val('tmChargeRPM', '<H', 0x28)
    set_val('tmInjBackTime', '<H', 0x2A)
    set_val('tmEjectTime', '<H', 0x2C)
    set_val('tmClpClsHighPres', '<H', 0x2E)
    set_val('tmInjHighPress', '<H', 0x30)
    set_val('tmChargeHighPress', '<H', 0x32)
    set_val('tmEjectAdvTime', '<H', 0x34)
    set_val('tmEjectRetTime', '<H', 0x36)

    set_val('tmInjMaxSpeed', '<H', 0x52)
    set_val('tmFetchTime', '<I', 0x54)

    # Side B
    set_val('tmInjTimeB', '<I', 0x64)
    set_val('tmTurnTimeB', '<I', 0x68)
    set_val('tmChargeTimeB', '<I', 0x6C)
    set_val('tmTurnPressB', '<H', 0x70)
    
    logger.info("deal_monitor parsed parameters.")

    # No response sent (Silent Handler)
