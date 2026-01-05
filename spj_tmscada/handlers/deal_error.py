import struct

def format_hmi_date_time(payload, date_offset, time_offset):
    """Helper to format HMI DATE and TIME structs into a string"""
    # DATE: bDay(1), bMonth(1), wYear(2), bWeek(1) -> 5 bytes + 1 byte padding/unknown
    d_day, d_month, d_year, d_week = struct.unpack_from('<BBHB', payload, date_offset)
    # TIME: bHour(1), bMinute(1), bSecond(1), bmSecond(1) -> 4 bytes
    t_hour, t_min, t_sec, t_msec = struct.unpack_from('<BBBB', payload, time_offset)
    
    if d_year == 0:
        return "N/A"
    return f"{d_year:04d}-{d_month:02d}-{d_day:02d} {t_hour:02d}:{t_min:02d}:{t_sec:02d}"

def deal_error(server, client_addr, data):
    """
    Handles PID 0x20001: Error/Alarm Telemetry
    Struct size: 26 bytes (payload)
    """
    payload = data[16:]
    if len(payload) < 26:
        return

    # Unpack basic error info
    error_code = struct.unpack_from('<H', payload, 0)[0]
    shot_count_at_error = struct.unpack_from('<I', payload, 2)[0] # Combining shotcount 1&2
    
    # Format Timestamps
    start_time = format_hmi_date_time(payload, 6, 12)
    fixed_time = format_hmi_date_time(payload, 16, 22)
    
    # Update Data Store
    server.data_store['LastError_Code'] = error_code
    server.data_store['LastError_ShotCount'] = shot_count_at_error
    server.data_store['LastError_StartTime'] = start_time
    server.data_store['LastError_FixedTime'] = fixed_time
    
    # Some logic uses a flag to indicate if an error is active
    server.data_store['IsErrorActive'] = 1 if fixed_time == "N/A" and error_code != 0 else 0

    # No response sent (Silent Handler)