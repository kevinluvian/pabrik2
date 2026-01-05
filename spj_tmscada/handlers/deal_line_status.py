import struct
import datetime
import logging
from tmscada_utils import crc32

logger = logging.getLogger(__name__)

def deal_line_status(server, addr, data):
    """
    Handles LineStatus packet (PID: 0x2000001).
    Sends TWO response packets.
    Ref: DealLineStatus in 54_manual_refactor.c
    """
    try:
        # --- PACKET 1 ---
        # Length 46 (0x2E), ID 0x1000000
        
        resp1 = bytearray(46)
        # Check data len
        if len(data) >= 16:
            resp1[:16] = data[:16]
        
        # Offset 2: Length = 46
        struct.pack_into('<H', resp1, 2, 46)
        # Offset 8: Version = 1
        struct.pack_into('<I', resp1, 8, 1)
        # Offset 12: Protocol ID = 0x1000000
        struct.pack_into('<I', resp1, 12, 0x1000000)
        
        # IP Address Logic (Offsets 0x10-0x13)
        try:
            ip_str = addr[0]
            ip_parts = [int(x) for x in ip_str.split('.')]
            if len(ip_parts) == 4:
                if ip_parts[3] == 0xff:
                    ip_parts[3] = 0xfe
                elif ip_parts[3] == 0xfe:
                    ip_parts[3] = 0xfd
                else:
                    ip_parts[3] += 1
                
                # Write modified IP to offsets 16-19 (0x10-0x13)
                struct.pack_into('4B', resp1, 0x10, *ip_parts)
                
                # LOG ARP ACTION
                logger.info(f"ARP Action (Simulated): arp -s {ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{ip_parts[3]} ...")
        except Exception as e:
            logger.error(f"Error parsing IP in deal_line_status: {e}")

        # Time Logic (Offsets 0x14-0x23)
        now = datetime.datetime.now()
        struct.pack_into('<H', resp1, 0x14, now.year)
        struct.pack_into('<H', resp1, 0x16, now.month)
        struct.pack_into('<H', resp1, 0x18, now.isoweekday()) 
        struct.pack_into('<H', resp1, 0x1a, now.day)
        struct.pack_into('<H', resp1, 0x1c, now.hour)
        struct.pack_into('<H', resp1, 0x1e, now.minute)
        struct.pack_into('<H', resp1, 0x20, now.second)
        msec = int(now.microsecond / 1000)
        struct.pack_into('<H', resp1, 0x22, msec)

        # CRC for Packet 1 (Offset 42, 0x2A)
        checksum_data1 = resp1[:42]
        crc1 = crc32(checksum_data1)
        struct.pack_into('<I', resp1, 42, crc1)
        
        logger.info(f"Sending LineStatus Packet 1 to {addr}")
        server.sock.sendto(resp1, addr)
        
        # --- PACKET 2 ---
        # Length 28 (0x1C), ID 0x1000001
        
        resp2 = bytearray(28)
        if len(data) >= 16:
            resp2[:16] = data[:16]
        
        # Offset 2: Length = 28
        struct.pack_into('<H', resp2, 2, 28)
        # Offset 8: Version = 1
        struct.pack_into('<I', resp2, 8, 1)
        # Offset 12: Protocol ID = 0x1000001
        struct.pack_into('<I', resp2, 12, 0x1000001)
        
        # CRC for Packet 2 (Offset 24, 0x18)
        checksum_data2 = resp2[:24]
        crc2 = crc32(checksum_data2)
        struct.pack_into('<I', resp2, 24, crc2)
        
        logger.info(f"Sending LineStatus Packet 2 to {addr}")
        server.sock.sendto(resp2, addr)

    except Exception as e:
        logger.error(f"Error in deal_line_status: {e}")
