import struct
import binascii

with open('handlers/samples/deal_get_moldset.txt', 'r') as f:
    hex_data = f.read().strip()

data = binascii.unhexlify(hex_data)
payload = data[16:]

# Header
wMhdrLength = struct.unpack('<H', payload[2:4])[0]
start_offset = 8 + wMhdrLength

# Function to check address
def check_addr(name, addr):
    offset = start_offset + (addr * 2)
    if offset + 2 <= len(payload):
        val = struct.unpack_from('<H', payload, offset)[0]
        print(f"{name} (Addr {addr}) at offset {offset}: {val}")
    else:
        print(f"{name} (Addr {addr}) at offset {offset}: Out of bounds (Len {len(payload)})")

check_addr("tmClpSPMode", 1301)
