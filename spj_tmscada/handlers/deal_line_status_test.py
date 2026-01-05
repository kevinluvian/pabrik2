import unittest
from unittest.mock import MagicMock
import binascii
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from handlers.deal_line_status import deal_line_status

class TestDealLineStatus(unittest.TestCase):
    def setUp(self):
        self.server = MagicMock()
        self.server.sock = MagicMock()
        self.client_addr = ('192.168.1.100', 12345)

    def _read_hex_from_file(self, filename):
        filepath = os.path.join(os.path.dirname(__file__), 'samples', filename)
        if not os.path.exists(filepath):
            self.fail(f"{filename} not found in handlers/samples/ directory.")
        with open(filepath, 'r') as f:
            return f.read().strip()

    def test_pid_line_status(self):
        hex_data = self._read_hex_from_file('deal_line_status.txt')
        data = binascii.unhexlify(hex_data)
        # Standardized call: (server, addr, data)
        deal_line_status(self.server, self.client_addr, data)
        # deal_line_status usually sends multiple responses
        self.server.sock.sendto.assert_called()

if __name__ == '__main__':
    unittest.main()
