import json
import os

filepath = 'wireshark_mitm_injection_tmscada_clean.json'

with open(filepath, 'r') as f:
    packets = json.load(f)

print(f"Loaded {len(packets)} packets")

for i, pkt in enumerate(packets[:5]):
    layers = pkt['_source']['layers']
    
    # Get IP src/dst
    ip_src = layers.get('ip', {}).get('ip.src')
    ip_dst = layers.get('ip', {}).get('ip.dst')
    
    # Get UDP payload
    # Wireshark JSON puts payload in 'data.data' (if data protocol) or 'udp.payload'
    # The snippet shows "data": { "data.data": "..." }
    
    payload_hex = None
    if 'data' in layers and 'data.data' in layers['data']:
        payload_hex = layers['data']['data.data']
    elif 'udp' in layers and 'udp.payload' in layers['udp']:
        payload_hex = layers['udp']['udp.payload']
        
    print(f"Packet {i}: {ip_src} -> {ip_dst} | Payload: {payload_hex is not None}")
