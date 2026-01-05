import struct
import logging
from precision_map import get_divisor

logger = logging.getLogger(__name__)

def deal_hmi_bound(server, client_addr, data):
    """
    Handles PID 0x20000 and 0x20001: Parameter Bounds (BOUND_AB)
    """
    logger.info(f"deal_hmi_bound received {len(data)} bytes from {client_addr}")
    
    # C code: memcpy(&bound_a, (void *)((int)pData + 0x260), 0xc0);
    # Offset 0x260 = 608.
    if len(data) < 0x260:
        logger.warning("deal_hmi_bound payload too short/incorrect offset")
        return
        
    payload = data[0x260:]
    
    # Helper to unpack and scale
    def set_val(key, fmt, offset):
        try:
            val = struct.unpack_from(fmt, payload, offset)[0]
            server.data_store[key] = val / get_divisor(key)
        except (struct.error, IndexError):
            # Not enough data for this field, ignore silently
            pass

    # --- MAX VALUES (Side A) ---
    # Offsets are relative to 0x260
    set_val('tmCycleTimeMax', '<I', 0x00)
    set_val('tmInjTimeMax', '<I', 0x04)
    set_val('tmTurnTimeMax', '<I', 0x08)
    set_val('tmChargeTimeMax', '<I', 0x0C)
    set_val('tmClpClsTimeMax', '<H', 0x10)
    set_val('tmClpOpnPosiMax', '<H', 0x16)
    set_val('tmClpOpnTimeMax', '<H', 0x18)
    set_val('tmTurnPressMax', '<H', 0x1A)
    set_val('tmInjStartPosiMax', '<H', 0x1C)
    set_val('tmTurnPosiMax', '<H', 0x1E)
    set_val('tmInjEndPosiMax', '<H', 0x20)
    set_val('tmInjBackTimeMax', '<H', 0x26)
    set_val('tmEjectTimeMax', '<H', 0x28)
    set_val('tmInjMaxPressMax', '<H', 0x2C)
    set_val('tmChargeMaxPressMax', '<H', 0x2E)

    # --- MIN VALUES (Side A) ---
    set_val('tmCycleTimeMin', '<I', 0x60)
    set_val('tmInjTimeMin', '<I', 0x64)
    set_val('tmTurnTimeMin', '<I', 0x68)
    set_val('tmChargeTimeMin', '<I', 0x6C)
    set_val('tmClpClsTimeMin', '<H', 0x70)
    set_val('tmClpOpnPosiMin', '<H', 0x76)
    set_val('tmClpOpnTimeMin', '<H', 0x78)
    set_val('tmTurnPressMin', '<H', 0x7A)
    set_val('tmInjStartPosiMin', '<H', 0x7C)
    set_val('tmTurnPosiMin', '<H', 0x7E)
    set_val('tmInjEndPosiMin', '<H', 0x80)
    set_val('tmInjBackTimeMin', '<H', 0x86)
    set_val('tmEjectTimeMin', '<H', 0x88)
    set_val('tmInjMaxPressMin', '<H', 0x8C)
    set_val('tmChargeMaxPressMin', '<H', 0x8E)
    
    # --- Side B Handling ---
    # C code: if (u_recvbuff_length < 0x353) ... else ... bound_ab
    # 0x353 = 851.
    if len(data) >= 851:
        # Offsets relative to 0x260 (start of payload slice)
        # Based on BOUND_AB struct analysis
        
        # Max Values B
        set_val('tmInjTimeMaxB', '<I', 0x120)
        set_val('tmTurnTimeMaxB', '<I', 0x124)
        set_val('tmChargeTimeMaxB', '<I', 0x128)
        set_val('tmTurnPressMaxB', '<H', 0x12C)
        set_val('tmInjStartPosiMaxB', '<H', 0x12E)
        set_val('tmTurnPosiMaxB', '<H', 0x130)
        set_val('tmInjEndPosiMaxB', '<H', 0x132)
        set_val('tmInjBackTimeMaxB', '<H', 0x138)
        set_val('tmEjectTimeMaxB', '<H', 0x13A)
        set_val('tmInjMaxPressMaxB', '<H', 0x140)
        set_val('tmChargeMaxPressMaxB', '<H', 0x142)

        # Min Values B
        set_val('tmInjTimeMinB', '<I', 0x150)
        set_val('tmTurnTimeMinB', '<I', 0x154)
        set_val('tmChargeTimeMinB', '<I', 0x158)
        set_val('tmTurnPressMinB', '<H', 0x15C)
        set_val('tmInjStartPosiMinB', '<H', 0x15E)
        set_val('tmTurnPosiMinB', '<H', 0x160)
        set_val('tmInjEndPosiMinB', '<H', 0x162)
        set_val('tmInjBackTimeMinB', '<H', 0x168)
        set_val('tmEjectTimeMinB', '<H', 0x16A)
        set_val('tmInjMaxPressMinB', '<H', 0x170)
        set_val('tmChargeMaxPressMinB', '<H', 0x172)
        
        # Additional mappings from C code (reusing A-side or specific offsets)
        # Assuming bound_ab.tmClpOpnTimeMax (0x18) maps to tmClpOpnTimeMaxB as per C logic analysis
        # But values differ in CSV, so proceeding with caution. 
        # Implementing explicit B-fields first.
        # tmClpOpnTimeMaxB is NOT in the B-struct explicit fields list I derived.
        # But tmClpOpnTimeMaxB IS in the CSV.
        
        # If C code does: s_value_ab[0x26] = bound_ab.tmClpOpnTimeMax;
        # And bound_ab.tmClpOpnTimeMax is at 0x18.
        # Then effectively:
        # server.data_store['tmClpOpnTimeMaxB'] = server.data_store['tmClpOpnTimeMax']
        # This matches the C code instruction.
        
        if 'tmClpOpnTimeMax' in server.data_store:
            server.data_store['tmClpOpnTimeMaxB'] = server.data_store['tmClpOpnTimeMax']

    logger.info("deal_hmi_bound parsed parameters.")
