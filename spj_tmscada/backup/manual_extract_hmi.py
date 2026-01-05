import struct
import binascii
import os

with open('handlers/samples/deal_hmi_bound.txt', 'r') as f:
    hex_data = f.read().strip()
if len(hex_data) % 2 != 0:
    hex_data += "0"
data = binascii.unhexlify(hex_data)

# C code uses offset 0x260 (608)
start_offset = 0x260

print(f"Data length: {len(data)}")
print(f"Reading from offset: {start_offset}")

# Helper to read
def read_val(name, fmt, offset_from_start):
    abs_offset = start_offset + offset_from_start
    if abs_offset + struct.calcsize(fmt) <= len(data):
        val = struct.unpack_from(fmt, data, abs_offset)[0]
        print(f"{name}: {val} (Hex: {val:x})")
    else:
        print(f"{name}: Out of bounds")

# Layout from deal_hmi_bound.py
# --- MAX VALUES (Side A) ---
read_val('tmCycleTimeMax', '<I', 0x00) # 4208
read_val('tmInjTimeMax', '<I', 0x04)
read_val('tmTurnTimeMax', '<I', 0x08)
read_val('tmChargeTimeMax', '<I', 0x0C)
read_val('tmClpClsTimeMax', '<H', 0x10)
read_val('tmClpOpnPosiMax', '<H', 0x16) # Note the gap in deal_hmi_bound.py? 
# deal_hmi_bound.py: 0x10, then 0x16. Gap of 4 bytes? 
# Let's check the struct layout implied.
# 0x10 (16) -> uint16 (2 bytes) -> 18.
# 0x16 (22). Bytes 18, 19, 20, 21 skipped?

# C struct `bound_a`:
# memcpy(&bound_a, ..., 0xc0); (192 bytes)
# If python handler has gaps, maybe it skips fields?
# Let's just read what the handler reads for now to verify non-zeros.

read_val('tmClpOpnPosiMax', '<H', 0x16)
read_val('tmClpOpnTimeMax', '<H', 0x18)
read_val('tmTurnPressMax', '<H', 0x1A)
read_val('tmInjStartPosiMax', '<H', 0x1C)
read_val('tmTurnPosiMax', '<H', 0x1E)
read_val('tmInjEndPosiMax', '<H', 0x20)
read_val('tmInjBackTimeMax', '<H', 0x26)
read_val('tmEjectTimeMax', '<H', 0x28)
read_val('tmInjMaxPressMax', '<H', 0x2C)
read_val('tmChargeMaxPressMax', '<H', 0x2E)

# --- MIN VALUES (Side A) ---
# deal_hmi_bound.py starts at 0x60 (96).
read_val('tmCycleTimeMin', '<I', 0x60)
read_val('tmInjTimeMin', '<I', 0x64)

# Also check Side B?
# C code: `memcpy(&bound_ab, (void *)((int)pData + 0x260), 0x180);`
# If len is large enough (>= 0x353), it reads `bound_a`.
# Else it reads `bound_ab`?
# In `deal_hmi_bound.txt`, `2403` -> 0x0324? No. `0200 2403`. 
# Wait, header analysis:
# `2403` -> `0x0324` (804).
# 804 > 0x353 (851)? No. 804 < 851.
# C code: `if (u_recvbuff_length < 0x353)` -> True for 804.
# `memcpy(&bound_a, ...)`
# So we are in the `bound_a` case.

# Let's confirm values.
