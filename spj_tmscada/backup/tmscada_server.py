import socket
import struct
import os
import sys
import binascii
import csv
import io

# --- Constants & Configuration ---
BIND_IP = '0.0.0.0'
BIND_PORT = 12345

# Protocol IDs
PID_STATUS_V2 = 0x2
PID_TEMPER    = 0x10000 
PID_MONITOR   = 0x20000 
PID_ERROR     = 0x21000 
PID_ENERGY    = 0x26000 
PID_INSTANT   = 0x40000 
PID_HANDSHAKE = 0x2000001 

# CSV Content
CSV_CONTENT = """tmClpOpnPress1,816,ns=1;i=16983592,02.成型参数(MoldParameter)/01.开模(ClampOpen)/tmClpOpnPress1,15,Float
tmClpOpnSpeed1,817,ns=1;i=16982692,02.成型参数(MoldParameter)/01.开模(ClampOpen)/tmClpOpnSpeed1,10,Float
tmClpOpnPosi1,818,ns=1;i=16983092,02.成型参数(MoldParameter)/01.开模(ClampOpen)/tmClpOpnPosi1,10,Float
tmTemp1_Set,928,ns=1;i=135342608,02.成型参数(MoldParameter)/08.温度(Temperature)/tmTemp1_Set,235,Float
tmTemp2_Set,929,ns=1;i=135342609,02.成型参数(MoldParameter)/08.温度(Temperature)/tmTemp2_Set,225,Float
tmTemp3_Set,930,ns=1;i=135342610,02.成型参数(MoldParameter)/08.温度(Temperature)/tmTemp3_Set,215,Float
tmTemp4_Set,931,ns=1;i=135342611,02.成型参数(MoldParameter)/08.温度(Temperature)/tmTemp4_Set,200,Float
tmMoldCavity,9035,ns=1;i=1125380,HMI1 数据库/01.即时参数(InstantParameter)/tmMoldCavity,1,UInt16
"""

# --- Globals ---
mold_buffer = bytearray()
mold_params = {}

# --- Initialization ---
def init_params():
    reader = csv.reader(io.StringIO(CSV_CONTENT))
    for row in reader:
        if len(row) >= 2:
            name = row[0].strip()
            try:
                addr = int(row[1])
                if addr != -1:
                    mold_params[name] = addr
            except:
                pass

init_params()

# --- Parsing Logic ---

def parse_header(data):
    if len(data) < 16: return None
    version, length, reserved, specia, direction, protocol_id = struct.unpack('<HHHHII', data[:16])
    protocol_id &= 0x3FFFFFFF
    return {
        'version': version, 'length': length, 'reserved': reserved,
        'specia': specia, 
        'direction': direction, 'protocol_id': protocol_id, 'payload': data[16:]
    }

def parse_temper(payload):
    if len(payload) < 84: return None
    d = {}
    d['tmShotCount'] = struct.unpack('<I', payload[0:4])[0]
    temps = struct.unpack('<' + 'H'*20, payload[4:44])
    d['tmTemp1_Current'] = temps[0]
    d['tmTemp2_Current'] = temps[1]
    d['tmTemp3_Current'] = temps[2]
    d['tmTemp4_Current'] = temps[3]
    return d

def parse_monitor(payload):
    if len(payload) < 130: return None
    d = {}
    d['tmShotCount'] = struct.unpack('<I', payload[0:4])[0]
    d['tmCycleTime'] = struct.unpack('<I', payload[4:8])[0]
    d['tmInjTime'] = struct.unpack('<I', payload[8:12])[0]
    d['tmTurnTime'] = struct.unpack('<I', payload[12:16])[0]
    d['tmChargeTime'] = struct.unpack('<I', payload[16:20])[0]
    d['tmClpClsTime'] = struct.unpack('<H', payload[20:22])[0]
    d['tmClpOpenTime'] = struct.unpack('<H', payload[28:30])[0]
    d['tmInjBackTime'] = struct.unpack('<H', payload[38:40])[0]
    d['tmEjectTime'] = struct.unpack('<H', payload[40:42])[0]
    
    d['tmFetchTime'] = struct.unpack('<I', payload[80:84])[0]
    d['tmInjTimeB'] = struct.unpack('<I', payload[96:100])[0]
    d['tmTurnTimeB'] = struct.unpack('<I', payload[100:104])[0]
    d['tmChargeTimeB'] = struct.unpack('<I', payload[104:108])[0]
    d['tmInjBackTimeB'] = struct.unpack('<H', payload[122:124])[0]
    d['tmEjectTimeB'] = struct.unpack('<H', payload[124:126])[0]
    return d

def parse_instant(payload):
    if len(payload) < 60: return None
    d = {}
    d['tmOperateMode'] = struct.unpack('<H', payload[2:4])[0]
    d['tmHeatState'] = struct.unpack('<H', payload[6:8])[0]
    d['tmMotorState'] = struct.unpack('<H', payload[8:10])[0]
    
    raw_id = payload[16:52] 
    try:
        craft_id = raw_id.decode('utf-8', errors='ignore').split('\x00')[0]
    except:
        craft_id = raw_id.hex()
    d['tmCraftIDstring'] = craft_id
    d['tmCraftID'] = craft_id
    return d

def parse_status_v2(payload):
    d = {}
    # Search for anchor "KC-JAMUR"
    # Offsets relative to start of KC-JAMUR:
    # ShotCount: +48 (4 bytes)
    # Temp1_Set: +56 (2 bytes)
    
    needle = b"KC-JAMUR"
    off = payload.find(needle)
    if off != -1:
        # Extract ID string (36 bytes like INSTANT)
        raw_id = payload[off:off+36]
        try:
            craft_id = raw_id.decode('utf-8', errors='ignore').split('\x00')[0]
        except:
            craft_id = raw_id.hex()
        d['tmCraftID'] = craft_id
        
        # ShotCount
        if len(payload) >= off + 52:
            d['tmShotCount'] = struct.unpack('<I', payload[off+48:off+52])[0]
            
        # Temperatures
        if len(payload) >= off + 74: # Need at least Temp1..Temp9 (9 words = 18 bytes)
            temps = struct.unpack('<' + 'H'*9, payload[off+56:off+74])
            d['tmTemp1_Set'] = temps[0]
            d['tmTemp2_Set'] = temps[1]
            d['tmTemp3_Set'] = temps[2]
            d['tmTemp4_Set'] = temps[3]
    return d

def handle_moldset_fragment(parsed):
    global mold_buffer
    frag_num = parsed['specia']
    if frag_num == 0:
        frag_num = parsed['protocol_id'] & 0xF
    
    payload = parsed['payload']
    
    if frag_num == 0:
        mold_buffer = bytearray()
        mold_buffer.extend(payload)
    else:
        mold_buffer.extend(payload)
    
    if len(mold_buffer) > 8:
        try:
            wSource, wMhdrLength, wLenA, wLenB = struct.unpack('<HHHH', mold_buffer[:8])
            
            # Fix for PCAP invalid header wMhdrLength=65535
            if wMhdrLength == 0xFFFF:
                data_start = 8 
            elif wMhdrLength > 10000:
                return None
            else:
                data_start = wMhdrLength + 8
            
            results = {}
            for name, addr in mold_params.items():
                offset = data_start + (addr * 2)
                if len(mold_buffer) >= offset + 2:
                     val_u16 = struct.unpack('<H', mold_buffer[offset:offset+2])[0]
                     results[name] = val_u16
            return results
        except Exception as e:
            return None
    return None

# --- Server Logic ---

def process_packet(data, addr, sock=None):
    parsed = parse_header(data)
    if not parsed: return

    pid = parsed['protocol_id']
    payload = parsed['payload']
    
    ptype = "UNKNOWN"
    info = ""
    
    if pid == PID_TEMPER:
        ptype = "TEMPER"
        d = parse_temper(payload)
        if d: 
            info = (
                    f"Shot:{d['tmShotCount']} "
                    f"T1:{d['tmTemp1_Current']} T2:{d['tmTemp2_Current']} "
                    f"T3:{d['tmTemp3_Current']} T4:{d['tmTemp4_Current']}")
            
    elif pid == PID_MONITOR:
        ptype = "MONITOR"
        d = parse_monitor(payload)
        if d: 
            info = (
                    f"Shot:{d['tmShotCount']} Cyc:{d['tmCycleTime']} Inj:{d['tmInjTime']} "
                    f"Chg:{d['tmChargeTime']} Ejt:{d['tmEjectTime']} "
                    f"InjB:{d['tmInjTimeB']} ChgB:{d['tmChargeTimeB']}")
    
    elif pid == PID_INSTANT:
        ptype = "INSTANT"
        d = parse_instant(payload)
        if d: 
            info = (
                    f"CraftID:{d['tmCraftIDstring']} "
                    f"Mode:{d['tmOperateMode']} Heat:{d['tmHeatState']} Motor:{d['tmMotorState']}")
            
    elif pid == PID_HANDSHAKE:
        ptype = "HANDSHAKE"
        info = f"Payload: {binascii.hexlify(payload).decode()}"
        
    elif pid == PID_STATUS_V2:
        ptype = "STATUS_V2"
        d = parse_status_v2(payload)
        if d:
            info = f"CraftID:{d.get('tmCraftID','?')} Shot:{d.get('tmShotCount','?')} "
            if 'tmTemp1_Set' in d:
                info += f"T1_Set:{d['tmTemp1_Set']} T2_Set:{d['tmTemp2_Set']}"
        
    elif (pid & 0xFFF0000) == 0x1020000 or (pid & 0xFFF0000) == 0x1010000: 
        ptype = "MOLDSET_FRAG"
        res = handle_moldset_fragment(parsed)
        if res:
             sample = ""
             keys_to_show = ["tmTemp1_Set", "tmTemp2_Set", "tmClpOpnPress1"]
             for k in keys_to_show:
                 if k in res: sample += f"{k}={res[k]} "
             info = f"Frag: {pid & 0xF} | {sample}"
        else:
             info = f"Frag: {pid & 0xF} | BuffLen: {len(mold_buffer)}"

    print(f"[{ptype}] From: {addr} | ID: 0x{pid:X} | Len: {len(payload)} | {info}")

# --- PCAPNG Parser ---

def read_pcapng_blocks(filename):
    try:
        with open(filename, 'rb') as f:
            while True:
                header = f.read(8)
                if len(header) < 8: break
                block_type, block_len = struct.unpack('<II', header)
                if block_len < 12: break
                body = f.read(block_len - 12)
                f.read(4)
                if block_type == 0x00000006:
                    if len(body) < 20: continue
                    cap_len = struct.unpack('<I', body[12:16])[0]
                    packet_data = body[20:20+cap_len]
                    if cap_len > 42:
                        eth_type = struct.unpack('>H', packet_data[12:14])[0]
                        if eth_type == 0x0800:
                            ip_len = (packet_data[14] & 0x0F) * 4
                            if packet_data[23] == 17:
                                udp_off = 14 + ip_len
                                sports, dports = struct.unpack('>HH', packet_data[udp_off:udp_off+4])
                                if sports == 12345 or dports == 12345:
                                    yield packet_data[udp_off+8:]
    except Exception as e:
        print(f"Error parsing PCAPNG: {e}")

def run_test_pcap():
    pcap_files = ["wireshark_mitm_injection_tmscada.pcapng", "wireshark_injection_laptop.pcapng"]
    print("-" * 60)
    print("Running PCAP Analysis Test")
    print("-" * 60)
    for pcap in pcap_files:
        if os.path.exists(pcap):
            print(f"\nProcessing {pcap}...")
            global mold_buffer
            mold_buffer = bytearray()
            for payload in read_pcapng_blocks(pcap):
                if len(payload) >= 16:
                    process_packet(payload, "PCAP")
            print("Done.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == 'run':
        server_loop()
    else:
        run_test_pcap()
