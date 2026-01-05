import struct
import logging
from tmscada_utils import crc32

logger = logging.getLogger(__name__)

def deal_online_status(server, addr, data):
    """
    Handles OnLineStatus packet (PID: 0x2000000).
    Ref: DealOnLineStatus in 54_manual_refactor.c
    """
    try:
        # Create a mutable bytearray from input data
        resp = bytearray(data)
        
        # Ensure buffer is large enough (at least 22 bytes for the response)
        if len(resp) < 22:
            resp.extend(b'\x00' * (22 - len(resp)))
        
        # Modify packet fields as per C logic
        # *(uint32_t *)((int)pData + 8) = 1;
        struct.pack_into('<I', resp, 8, 1)
        
        # *(byte *)((int)pData + 0xf) = *(byte *)((int)pData + 0xf) & 0x3f;
        resp[0xf] &= 0x3f
        
        # *(uint8_t *)((int)pData + 0xe) = 0;
        resp[0xe] = 0
        
        # *(byte *)((int)pData + 0xf) = *(byte *)((int)pData + 0xf) & 0xc0;
        resp[0xf] &= 0xc0
        
        # *(uint16_t *)((int)pData + 0xc) = 0;
        struct.pack_into('<H', resp, 0xc, 0)
        
        # *(uint16_t *)((int)pData + 2) = 0x16; (Length 22)
        struct.pack_into('<H', resp, 2, 0x16)
        
        # *(uint16_t *)((int)pData + 0x10) = 1;
        struct.pack_into('<H', resp, 0x10, 1)
        
        # Calculate CRC
        checksum_data = resp[:0x12]
        crc = crc32(checksum_data)
        
        # *(ulong *)((int)pData + 0x12) = testdw_id;
        struct.pack_into('<I', resp, 0x12, crc)
        
        # Final response packet (22 bytes)
        final_packet = resp[:22]
        
        logger.info(f"Sending OnLineStatus response to {addr}, len={len(final_packet)}")
        server.sock.sendto(final_packet, addr)
        
    except Exception as e:
        logger.error(f"Error in deal_online_status: {e}")