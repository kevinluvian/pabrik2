import struct
import logging

logger = logging.getLogger(__name__)

def deal_version(server, addr, data):
    """
    Handles PID 0x1010000: Protocol Version Check
    Ref: DealVersion in 54_manual_refactor.c
    """
    logger.info(f"deal_version received {len(data)} bytes from {addr}")
    
    # Parse Globals from Input
    try:
        if len(data) >= 48:
            server.data_store['g_machine_type'] = struct.unpack_from('<H', data, 26)[0]
            server.data_store['g_style_type'] = struct.unpack_from('<H', data, 28)[0]
            server.data_store['g_MAX_Temp'] = struct.unpack_from('<H', data, 32)[0]
            server.data_store['g_SPEED_Precious'] = struct.unpack_from('<H', data, 34)[0]
            server.data_store['g_Position_Precious'] = struct.unpack_from('<H', data, 46)[0]
            
            logger.info(f"Parsed Version Info: MachineType={server.data_store.get('g_machine_type')}")
    except Exception as e:
        logger.warning(f"Failed to parse/store version info: {e}")

    # SendBoundApplication logic
    # Hardcoded packet: 02 00 00 00 00 00 00 00 01 00 00 00 04 00 00 42 01 00
    resp = bytearray(18)
    resp[0] = 0x02
    resp[8] = 0x01
    resp[12] = 0x04
    resp[15] = 0x42 # 'B'
    resp[16] = 0x01
    
    logger.info(f"Sending SendBoundApplication response to {addr}")
    server.sock.sendto(resp, addr)