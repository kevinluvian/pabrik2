import struct
import logging
from tmscada_utils import crc32

logger = logging.getLogger(__name__)

def deal_identification_a(server, addr, data):
        """
        Handles Identification A packet (PID: 0x100000a).
        Ref: DealidentificationA in 54_manual_refactor.c
        """
        try:
            # Create a mutable bytearray from input data
            resp = bytearray(data)
            
            # Ensure buffer is large enough (at least 22 bytes for the response)
            if len(resp) < 22:
                resp.extend(b'\x00' * (22 - len(resp)))
            
            # Modify packet fields as per C logic:
            # Offset 8: dwReserved/Version = 1
            struct.pack_into('<I', resp, 8, 1)
            
            # Offset 12: dwProtocolID = 0x200000a (Response ID)
            struct.pack_into('<I', resp, 12, 0x200000a)
            
            # Offset 2: dwLength = 0x16 (22 bytes)
            struct.pack_into('<H', resp, 2, 0x16)
            
            # Offset 16: wFlag = 0xff
            struct.pack_into('<H', resp, 16, 0xff)
            
            # Calculate CRC32 of the first 18 bytes (0x12)
            checksum_data = resp[:18]
            crc = crc32(checksum_data)
            
            # Offset 18: Store CRC32
            struct.pack_into('<I', resp, 18, crc)
            
            # Final response packet (22 bytes)
            final_packet = resp[:22]
            
            logger.info(f"Sending Identification A response to {addr}, len={len(final_packet)}")
            server.sock.sendto(final_packet, addr)
            
        except Exception as e:
            logger.error(f"Error in deal_identification_a: {e}")
