import struct

def deal_energy(server, client_addr, data):
    """
    Handles PID 0x20006: Energy Consumption Telemetry
    Struct size: 4 bytes (payload)
    """
    payload = data[16:]
    if len(payload) < 4:
        return

        # Unpack tmTotalEnergyConsumption (DWORD at offset 0)

        energy_val = struct.unpack_from('<I', payload, 0)[0]

        server.data_store['tmTotalEnergyConsumption'] = energy_val

    

        # No response sent (Silent Handler)

    