import unittest
from unittest.mock import MagicMock
import binascii
import os
import sys

# Add project root to sys.path to allow imports if running from handlers/
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from handlers.deal_identification_a import deal_identification_a

class TestDealIdentificationA(unittest.TestCase):
    def setUp(self):
        self.server = MagicMock()
        self.server.data_store = {}
        self.server.sock = MagicMock()
        self.client_addr = ('192.168.1.100', 12345)

    def _read_hex_from_file(self, filename):
        filepath = os.path.join(os.path.dirname(__file__), 'samples', filename)
        if not os.path.exists(filepath):
            self.fail(f"{filename} not found in handlers/samples/ directory.")
        with open(filepath, 'r') as f:
            return f.read().strip()

    def test_pid_identification_a(self):
        hex_data = self._read_hex_from_file('deal_identification_a.txt')
        data = binascii.unhexlify(hex_data)
        
        # Standardized call: (server, addr, data)
        deal_identification_a(self.server, self.client_addr, data)
        
        self.server.sock.sendto.assert_called()
        args, _ = self.server.sock.sendto.call_args
        resp = args[0]
        self.assertEqual(len(resp), 22)
        import struct
        self.assertEqual(struct.unpack_from('<I', resp, 8)[0], 1)

if __name__ == '__main__':
    unittest.main()