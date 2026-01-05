import struct
import logging

logger = logging.getLogger(__name__)

def deal_machine_status(server, addr, data):
    """
    Handles PID 0x40000: Operational State Telemetry (OPERSTATE)
    Struct size: 76 (0x4C) or 88 (0x58) bytes (payload)
    Ref: DealMachineStatus and OPERSTATE struct definition
    """
    logger.info(f"deal_machine_status received {len(data)} bytes from {addr}")
    
    payload = data[16:]
    
    if len(payload) < 76:
        logger.warning(f"deal_machine_status payload too short: {len(payload)}")
        return

    # --- 0x00 - 0x10: Basic States ---
    # wProdState (0), wOperState (2), wErrorState (4), wHeatState (6), wMotorState (8)
    # tmInferior (10), wReverse (14)
    
    states = struct.unpack_from('<5H', payload, 0x00)
    wProdState = states[0]
    wOperState = states[1]
    wErrorState = states[2]
    wHeatState = states[3]
    wMotorState = states[4]
    
    server.data_store['wProdState'] = wProdState
    server.data_store['wOperState'] = wOperState
    server.data_store['wErrorState'] = wErrorState
    server.data_store['wHeatState'] = wHeatState
    server.data_store['wMotorState'] = wMotorState
    
    # Map to Requested Keys
    server.data_store['tmOperateMode'] = wOperState
    server.data_store['tmHeatState'] = wHeatState
    server.data_store['tmMotorState'] = wMotorState
    
    # tmAlarmState Logic
    if wErrorState == 0xFFFF: # 65535
        tmAlarmState = 0
        tmAlarmID = 0
    else:
        tmAlarmState = 1
        tmAlarmID = wErrorState
        
    server.data_store['tmAlarmState'] = tmAlarmState
    server.data_store['tmAlarmID'] = tmAlarmID
    
    server.data_store['tmInferior'] = struct.unpack_from('<I', payload, 0x0A)[0]
    
    # --- 0x10 (16) - 0x34 (52): wTEST (36 bytes) ---
    def decode_str(b):
        return b.decode('latin1', errors='ignore').strip('\x00')

    server.data_store['tmCraftID'] = decode_str(payload[16:30])
    server.data_store['tmMaterial'] = decode_str(payload[36:42])
    server.data_store['tmColor'] = decode_str(payload[42:48])
    server.data_store['tmMoldCavity'] = struct.unpack_from('<H', payload, 48)[0]

    # --- 0x34 (52) - 0x58 (88): Counters and Energy ---
    prod_stats = struct.unpack_from('<3I', payload, 52)
    server.data_store['tmPlanCount'] = prod_stats[0]
    server.data_store['dwShotCountCurrent'] = prod_stats[1]
    server.data_store['dwCycleTime'] = prod_stats[2]
    
    # Map dwShotCountCurrent to tmShotCount
    server.data_store['tmShotCount'] = prod_stats[1]
    
    server.data_store['tmLotNumber'] = struct.unpack_from('<H', payload, 64)[0]
    
    # Check for 88 byte payload for Energy fields
    if len(payload) >= 88:
        server.data_store['tmPowerConsumptionRatio'] = struct.unpack_from('<H', payload, 80)[0]
        server.data_store['tmPowerConsumption'] = struct.unpack_from('<I', payload, 82)[0]
        server.data_store['tmBadShotCount'] = struct.unpack_from('<H', payload, 86)[0]
        
        logger.info(f"deal_machine_status parsed full 88 bytes.")
    else:
        logger.info(f"deal_machine_status parsed 76 bytes (partial).")
        
    logger.info(f"Parsed: Prod={wProdState}, ID={server.data_store['tmCraftID']}, Shot={server.data_store['tmShotCount']}")