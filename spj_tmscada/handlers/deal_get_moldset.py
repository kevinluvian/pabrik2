import struct
import xml.etree.ElementTree as ET
import os
import logging
import binascii

logger = logging.getLogger(__name__)

def load_mold_map(file_path="tmscada/MoldData_54_52.xml"):
    """
    Parses the MoldData XML to extract address and precision for each parameter.
    Returns a dict: {Name: {'address': int, 'precision': int}}
    """
    mapping = {}
    if not os.path.exists(file_path):
        logger.error(f"XML File not found at {file_path}")
        return mapping
        
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        for item in root.findall('iNetData'):
            name_elem = item.find('Name')
            addr_elem = item.find('MoldSetAddress54')
            prec_elem = item.find('MoldSetPrecision54')
            if name_elem is not None and addr_elem is not None and prec_elem is not None:
                name = name_elem.text
                try:
                    address = int(addr_elem.text)
                    precision = int(prec_elem.text)
                    mapping[name] = {'address': address, 'precision': precision}
                except (ValueError, TypeError):
                    print('error parse', name_elem)
                    continue
    except Exception as e:
        logger.error(f"Error loading mold map: {e}")

    return mapping

def deal_get_moldset(server, client_addr, data):
    logger.info(f"deal_get_moldset received {len(data)} bytes from {client_addr}")
    # logger.debug(f"Raw data: {binascii.hexlify(data).decode('ascii')}")

    if len(data) < 16:
        return

    # Load mapping if not present
    if not getattr(server, 'mold_map', None):
        server.mold_map = load_mold_map()

    # Initialize buffer if not present
    if not getattr(server, 'mold_data_buffer', None):
        server.mold_data_buffer = bytearray(65536) # Arbitrary large size
        server.mold_data_received_len = 0

    # Packet Header Analysis
    packet_num = struct.unpack('<H', data[6:8])[0]
    
    payload = data[16:]
    
    # Store payload into buffer
    if packet_num == 0:
        server.mold_data_buffer[0:len(payload)] = payload
        server.mold_data_received_len = len(payload)
    else:
        # Append logic (simplified)
        current_len = server.mold_data_received_len
        server.mold_data_buffer[current_len:current_len+len(payload)] = payload
        server.mold_data_received_len += len(payload)

    # Parse Data
    buffer = server.mold_data_buffer
    valid_len = server.mold_data_received_len
    
    if valid_len < 8:
        return

    # Extract wMhdrLength
    w_mhdr_length = struct.unpack('<H', buffer[2:4])[0]
    
    # Calculate Data Start Offset
    data_start_offset = 8 + w_mhdr_length
    
    # Assume global flag g_SPEED_Precious is 999 for the logic below
    g_SPEED_Precious = 999 

    parsed_count = 0
    parsed_data = []
    for name, info in server.mold_map.items():
        address = info['address']
        precision = info['precision']
        
        if address == -1:
            continue

        byte_offset = data_start_offset + (address * 2)
        is_4_byte = (precision == 101)
        data_size = 4 if is_4_byte else 2

        if byte_offset + data_size <= valid_len:
            try:
                if is_4_byte:
                    raw_val = struct.unpack_from('<I', buffer, byte_offset)[0]
                    # Check for -1 sentinel
                    if raw_val == 0xFFFFFFFF:
                         server.data_store[name] = -1
                         parsed_data.append((name, -1))
                         parsed_count += 1
                         continue
                else:
                    raw_val = struct.unpack_from('<H', buffer, byte_offset)[0]
                    # Check for -1 sentinel
                    if raw_val == 0xFFFF:
                         server.data_store[name] = -1
                         parsed_data.append((name, -1))
                         parsed_count += 1
                         continue
                
                # Apply Precision Mapping Logic
                mapped_precision = precision 
                
                if precision == 11:
                    if g_SPEED_Precious == 999:
                        mapped_precision = 1
                    else:
                        mapped_precision = 0
                elif precision == 1:
                    mapped_precision = 0
                elif precision == 10:
                    mapped_precision = 1
                elif precision == 100:
                    mapped_precision = 2
                elif precision == 101:
                    mapped_precision = 2
                
                # Apply Divisor
                divisor = 1.0
                if mapped_precision == 1:
                    divisor = 10.0
                elif mapped_precision == 2:
                    divisor = 100.0
                elif mapped_precision == 3:
                    divisor = 1000.0
                elif mapped_precision == 4:
                    divisor = 10000.0
                elif mapped_precision == 5:
                    divisor = 100000.0
                
                if divisor == 1.0:
                    val = raw_val
                else:
                    val = raw_val / divisor
                
                server.data_store[name] = val
                parsed_data.append((name, val))
                parsed_count += 1
            except Exception:
                pass
    
    logger.info(f"deal_get_moldset parsed {parsed_count} parameters.")
    for item in parsed_data:
        print(item)