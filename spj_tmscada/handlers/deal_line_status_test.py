import unittest
import struct
import binascii
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from handlers.deal_line_status import deal_line_status

class TestDealLineStatus(unittest.TestCase):
    def setUp(self):
        self.server = MagicMock()
        self.server.sock = MagicMock()
        self.client_addr = ('192.168.13.100', 12345)

    def test_tmscada_box_replay(self):
        """
        Verifies behavior against the captured tmScada box traffic.
        Input Payload: 02001a00000001000000000001000042d4e95e16e22c32b3e99d
        Expected Logic:
        1. Extract MAC (d4e95e16e22c)
        2. Calculate IP (Server IP .150 -> .151)
        3. Send Packet 1 (46 bytes) with IP + MAC + Time
        4. Send Packet 2 (28 bytes) with zeros + PID 0x1000001
        """
        req_hex = "02001a00000001000000000001000042d4e95e16e22c32b3e99d"
        req_data = binascii.unhexlify(req_hex)
        
        # We assume the server IP is 192.168.13.150 to match the observed reply of .151
        with patch('handlers.deal_line_status.get_local_ip', return_value="192.168.13.150"):
            deal_line_status(self.server, self.client_addr, req_data)
            
        # Verify 2 packets sent
        self.assertEqual(self.server.sock.sendto.call_count, 2)
        
        # --- Packet 1 Verification ---
        args1, _ = self.server.sock.sendto.call_args_list[0]
        resp1 = args1[0]
        
        # Length check
        self.assertEqual(len(resp1), 46, "Packet 1 length should be 46")
        
        # Header check (PID 0x1000000)
        self.assertEqual(resp1[12:16].hex(), "00000001", "Packet 1 PID incorrect")
        
        # IP Check (Offset 16) -> 192.168.13.151 (c0 a8 0d 97)
        self.assertEqual(resp1[16:20].hex(), "c0a80d97", "Calculated IP incorrect")
        
        # MAC Check (Offset 36) -> d4e95e16e22c
        self.assertEqual(resp1[36:42].hex(), "d4e95e16e22c", "Copied MAC incorrect")
        
        # --- Packet 2 Verification ---
        args2, _ = self.server.sock.sendto.call_args_list[1]
        resp2 = args2[0]
        
        # Length check
        self.assertEqual(len(resp2), 28, "Packet 2 length should be 28")
        
        # Header check (PID 0x1000001)
        self.assertEqual(resp2[12:16].hex(), "01000001", "Packet 2 PID incorrect")
        
        # Padding Check (16-24) -> All Zeros
        self.assertEqual(resp2[16:24].hex(), "0000000000000000", "Packet 2 padding not zero")

if __name__ == '__main__':
    unittest.main()