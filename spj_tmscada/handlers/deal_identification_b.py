import struct
import logging
import base64
from tmscada_utils import crc32, encrypt_string, decrypt_string, rsa_sign_data

logger = logging.getLogger(__name__)

def deal_identification_b(server, addr, data):
    """
    Handles Identification B packet (PID: 0x100000b).
    Ref: DealidentificationB in 54_manual_refactor.c
    """
    try:
        wLength = len(data)
        
        if wLength < 0x65:
            # Mode 1: Self Encryption (Custom Algorithm)
            # Input length at offset 16 (0x10)
            if wLength < 18: return
            input_len = struct.unpack_from('<H', data, 16)[0]
            
            # Payload at offset 18 (0x12)
            payload = data[18 : 18 + input_len]
            
            # Decrypt -> Encrypt Loop
            decrypted = decrypt_string(payload)
            encrypted = encrypt_string(decrypted)
            
            # Construct Response
            resp = bytearray(60)
            resp[:16] = data[:16]
            
            # Offset 8: Version = 1
            struct.pack_into('<I', resp, 8, 1)
            # Offset 12: Protocol ID = 0x200000b
            struct.pack_into('<I', resp, 12, 0x200000b)
            
            # "sendbuf[0x10] = ' '; sendbuf[0x11] = '\0';"
            resp[16] = 0x20 # Space
            resp[17] = 0x00
            
            # Copy encrypted payload to 0x12
            enc_len = min(len(encrypted), 32)
            resp[18 : 18 + enc_len] = encrypted[:enc_len]
            
            # Offset 2: Length = 0x36 (54 bytes)
            struct.pack_into('<H', resp, 2, 0x36)
            
            # CRC at offset 50 (0x32)
            checksum_data = resp[:50]
            crc = crc32(checksum_data)
            struct.pack_into('<I', resp, 50, crc)
            
            final_packet = resp[:54]
            logger.info(f"Sending Identification B (Self) response to {addr}")
            server.sock.sendto(final_packet, addr)
            
        else:
            # Mode 2: RSA Encryption
            input_len = struct.unpack_from('<H', data, 16)[0]
            # Payload is Base64 encoded string
            payload_b64 = data[18 : 18 + input_len]
            
            try:
                payload_bytes = base64.b64decode(payload_b64)
            except Exception:
                payload_bytes = payload_b64 # Fallback if not b64?
            
            # RSA Sign (Decrypt -> Hash -> Sign)
            signature_b64 = rsa_sign_data(payload_bytes)
            
            # MOCK for testing without cryptography lib
            if signature_b64 is None:
                # Check if payload matches the known sample (partial match)
                if payload_b64.startswith(b'QLJXA'):
                    pass

            if signature_b64:
                sig_len = len(signature_b64)
                
                resp = bytearray(data[:18]) # Header + Size field space
                resp.extend(signature_b64) # Append signature
                
                total_len = 18 + sig_len + 4 # Header + Sig + CRC
                
                # Update fields
                struct.pack_into('<H', resp, 2, total_len) # Length
                struct.pack_into('<I', resp, 8, 1) # Version
                struct.pack_into('<I', resp, 12, 0x200000b) # ID
                struct.pack_into('<H', resp, 16, sig_len) # Sig Size
                
                # CRC
                checksum_data = resp[: 18 + sig_len]
                crc = crc32(checksum_data)
                
                # Append CRC
                resp.extend(struct.pack('<I', crc))
                
                logger.info(f"Sending Identification B (RSA) response to {addr}, len={len(resp)}")
                server.sock.sendto(resp, addr)
            else:
                logger.error("RSA Signature failed (missing key/lib?), dropping packet.")

    except Exception as e:
        logger.error(f"Error in deal_identification_b: {e}")
