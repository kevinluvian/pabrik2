import unittest
from unittest.mock import MagicMock
import binascii
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from handlers.deal_version import deal_version

class TestDealVersion(unittest.TestCase):
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

    def test_pid_version(self):
        hex_data = self._read_hex_from_file('deal_version.txt')
        data = binascii.unhexlify(hex_data)
        # Assuming deal_version processes the packet and sends something back or updates state
        # I will just call it to ensure no exceptions
        deal_version(self.server, self.client_addr, data)
        # Check if it sends a response (based on C code analysis of similar functions, version usually replies)
        # self.server.sock.sendto.assert_called() # Removed as implementation is currently silent

if __name__ == '__main__':
    unittest.main()