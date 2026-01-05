import struct
import logging

logger = logging.getLogger(__name__)

def deal_update(server, client_addr, data):
    """
    Handles PID 0x10003: Parameter Modification (MODIFY)
    Struct size: 72 bytes (payload)
    """
    payload = data[16:]
    if len(payload) < 72:
        return

    # Unpack basic info
    wDataType = struct.unpack_from('<H', payload, 0)[0]
    cLoginID = payload[2:10].decode('ascii', errors='ignore').strip('\x00')
    wDataID = struct.unpack_from('<H', payload, 10)[0]

    # Handle Union based on DataType
    # (Simplified: we'll store all representations)
    old_val_w, new_val_w = struct.unpack_from('<HH', payload, 12)
    old_val_dw, new_val_dw = struct.unpack_from('<II', payload, 12)
    
    log_msg = f"Update Request: User='{cLoginID}', DataID=0x{wDataID:x}, Type={wDataType}"
    
    if wDataType == 1: # WORD
        logger.info(f"{log_msg}, Val: {old_val_w} -> {new_val_w}")
        # Update data_store if we know the ID mapping (using generic name for now)
        server.data_store[f'Param_0x{wDataID:x}'] = new_val_w
    elif wDataType == 2: # DWORD
        logger.info(f"{log_msg}, Val: {old_val_dw} -> {new_val_dw}")
        server.data_store[f'Param_0x{wDataID:x}'] = new_val_dw
    else: # Array/Buffer
        buffer = struct.unpack_from('<30H', payload, 12)
        logger.info(f"{log_msg}, Buffer Update")
        server.data_store[f'Param_0x{wDataID:x}'] = list(buffer)

    # No response sent (Silent Handler as per C logic)