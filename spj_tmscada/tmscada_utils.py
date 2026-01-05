import zlib
import struct
import logging

logger = logging.getLogger(__name__)

def crc32(data):
    """
    Calculates CRC32 matching the C implementation (GetCRC32).
    It effectively computes standard CRC32 but without the final XOR with 0xFFFFFFFF.
    zlib.crc32 returns result WITH final XOR.
    So we invert it back: ~zlib.crc32(data) & 0xFFFFFFFF.
    """
    return ~zlib.crc32(data) & 0xFFFFFFFF

def encrypt_string(input_bytes):
    """
    Custom Encryption Logic from EncryptString in C.
    Permutes first 5 bytes of every 10-byte block (Reverse 0-4).
    Adds offset j (1..10) to bytes.
    """
    if not input_bytes:
        return b""
    
    input_len = len(input_bytes)
    output = bytearray(input_len)
    
    # 1. Permutation Phase
    # Loops through 10-byte blocks
    for i in range(input_len):
        block_idx = i % 10
        base_idx = (i // 10) * 10
        
        if block_idx < 5:
            # Swap 0->4, 1->3, 2->2, etc.
            target_idx = base_idx + (4 - block_idx)
            # Ensure target is within bounds (though C logic implies full blocks or careful length)
            if target_idx < input_len:
                output[target_idx] = input_bytes[i]
            else:
                output[i] = input_bytes[i] # Fallback? C doesn't check bounds explicitly in snippet
        else:
            # Keep 5-9 as is
            output[i] = input_bytes[i]
            
    # 2. Shift Phase
    j = 0
    final_output = bytearray(input_len)
    for i in range(input_len):
        j += 1
        val = output[i] + j
        final_output[i] = val & 0xFF # Wrap to byte
        if j == 10:
            j = 0
            
    return final_output

def decrypt_string(input_bytes):
    """
    Custom Decryption Logic from DecryptString in C.
    Subtracts offset j (1..10).
    Permutes last 5 bytes of every 10-byte block (Reverse 5-9).
    (Based on C code analysis: if i%10 < 5: out[i]=temp[i] else out[...]=temp[i])
    """
    if not input_bytes:
        return b""
        
    input_len = len(input_bytes)
    temp = bytearray(input_len)
    
    # 1. Shift Back Phase
    j = 0
    for i in range(input_len):
        j += 1
        val = input_bytes[i] - j
        temp[i] = val & 0xFF
        if j == 10:
            j = 0
            
    # 2. Permutation Phase
    output = bytearray(input_len)
    for i in range(input_len):
        block_idx = i % 10
        base_idx = (i // 10) * 10
        
        if block_idx < 5:
            # Keep 0-4 as is
            output[i] = temp[i]
        else:
            # Reverse 5-9: 5->9, 6->8, 7->7, 8->6, 9->5 (14 - i%10)
            target_idx = base_idx + (14 - block_idx)
            if target_idx < input_len:
                output[target_idx] = temp[i]
            else:
                output[i] = temp[i]
                
    return output

# RSA Placeholder
def rsa_sign_data(data, key_path='tmscada/privkey_2049.pem'):
    """
    Decrypts data using RSA Private Key and then Signs it.
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
        import base64
        
        with open(key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            
        # 1. RSA Decrypt (PKCS1v15 padding implied by C's RSA_private_decrypt)
        # Note: C code uses RSA_private_decrypt with padding=1 (RSA_PKCS1_PADDING)
        decrypted = private_key.decrypt(
            data,
            padding.PKCS1v15()
        )
        
        # 2. SHA256 Hash
        # C code: SHA256((uchar *)data, ..., md) -> But wait, C code hashes the DECRYPTED data?
        # "SHA256((uchar *)data, ptf_en_length, md);" -> variable name 'data' in C usually refers to the decrypted buffer?
        # Check C code: __s = my_decrypt(...); ptf_en_length = strlen(__s); SHA256(__s...);
        # Yes, hashes the decrypted string.
        
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(decrypted)
        hashed_data = digest.finalize()
        
        # 3. RSA Sign
        # C code: RSA_sign(NID_sha256, md, ..., sig, ..., privKey);
        # This creates a signature of the hash.
        signature = private_key.sign(
            decrypted, # sign() method usually handles hashing, but we need to match OpenSSL RSA_sign behavior
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # 4. Base64 Encode Signature?
        # C code: test = b64_encode(sig, nOutLen); strcpy(signmes.signature, test);
        sig_b64 = base64.b64encode(signature)
        
        return sig_b64
        
    except ImportError:
        logger.error("Cryptography library not found. RSA handshake will fail.")
        return None
    except Exception as e:
        logger.error(f"RSA Error: {e}")