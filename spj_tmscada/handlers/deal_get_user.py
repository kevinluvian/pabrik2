import struct

def deal_get_user(server, client_addr, data):
    """
    Handles PID 0x2000c: User Table Telemetry
    Struct size: 104 bytes (4 users * 26 bytes each)
    """
    payload = data[16:]
    if len(payload) < 104:
        return

    users = []
    for i in range(4):
        offset = i * 26
        # szUserID[8], szPassword[8], szName[8], wPriv[2]
        user_data = struct.unpack_from('<8s8s8sH', payload, offset)
        
        user_info = {
            'UserID': user_data[0].decode('ascii', errors='ignore').strip('\x00'),
            'Password': user_data[1].decode('ascii', errors='ignore').strip('\x00'),
            'Name': user_data[2].decode('ascii', errors='ignore').strip('\x00'),
            'Privilege': user_data[3]
        }
        users.append(user_info)
        
        # Store in data_store using index
        server.data_store[f'User_{i}_ID'] = user_info['UserID']
        server.data_store[f'User_{i}_Name'] = user_info['Name']
        server.data_store[f'User_{i}_Priv'] = user_info['Privilege']

    # No response sent (Silent Handler)