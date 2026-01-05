import struct

def deal_inferior_status(server, client_addr, data):
    """
    Handles PID 0x40003: Inferior Status (Bad Shot Count)
    Reads a DWORD at payload offset 0x16 (Packet Offset 0x26).
    """
    payload = data[16:]
    # Offset 0x26 (38) minus Header (16) = 22 (0x16)
    if len(payload) < 26: # Need at least 22 + 4 bytes
        return

    # Unpack tmInferior
    inferior_count = struct.unpack_from('<I', payload, 22)[0]
    
    server.data_store['tmInferior'] = inferior_count

    # No response sent (Silent Handler)