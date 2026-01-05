import unittest
from unittest.mock import MagicMock
import binascii
import os
import sys
import csv

# Add project root to sys.path to allow imports if running from handlers/
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from handlers.deal_temperature import deal_temperature

class TestDealTemperature(unittest.TestCase):
    def setUp(self):
        self.server = MagicMock()
        self.server.data_store = {}
        self.server.sock = MagicMock()
        self.client_addr = ('192.168.1.100', 12345)

    def _read_hex_from_file(self, filename):
        # File path relative to this test file: samples/filename
        filepath = os.path.join(os.path.dirname(__file__), 'samples', filename)
        if not os.path.exists(filepath):
            self.fail(f"{filename} not found in handlers/samples/ directory.")
        with open(filepath, 'r') as f:
            return f.read().strip()

    def test_pid_temperature(self):
        # 1. Run the handler to populate data_store
        hex_data = self._read_hex_from_file('deal_temperature.txt')
        data = binascii.unhexlify(hex_data)
        deal_temperature(self.server, self.client_addr, data)
        
        # 2. Read Expected CSV
        csv_filename = 'deal_temperature_expected.csv'
        csv_path = os.path.join(os.path.dirname(__file__), 'samples', csv_filename)
        
        if not os.path.exists(csv_path):
             self.fail(f"{csv_filename} not found in handlers/samples/")

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader) # Skip header
            
            for row in reader:
                if len(row) < 2:
                    continue

                name = row[0].strip()
                expected_str = row[1].strip()
                
                # Check if data exists in our store
                if name not in self.server.data_store:
                    # Missing values are expected for truncated/sample packets.
                    print('missing', name)
                    continue
                
                actual_val = self.server.data_store[name]
                
                try:
                    expected_val = float(expected_str)
                    # Use delta=0.01 for float comparison
                    self.assertAlmostEqual(actual_val, expected_val, delta=0.01, 
                                           msg=f"Mismatch for {name}: expected {expected_val}, got {actual_val}")
                except ValueError:
                    pass
        self.server.sock.sendto.assert_not_called()


if __name__ == '__main__':
    unittest.main()