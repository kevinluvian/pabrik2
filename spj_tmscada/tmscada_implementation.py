import socket
import struct
import logging
import sys
import binascii
import signal
from prometheus_client import start_http_server
from tmscada_metrics import update_metric, PACKET_COUNT

# Import individual handlers
from handlers.deal_temperature import deal_temperature
from handlers.deal_monitor import deal_monitor
from handlers.deal_update import deal_update
from handlers.deal_hmi_bound import deal_hmi_bound
from handlers.deal_error import deal_error
from handlers.deal_energy import deal_energy
from handlers.deal_machine_status import deal_machine_status
from handlers.deal_inferior_status import deal_inferior_status
from handlers.deal_xml import deal_xml
from handlers.deal_identification_a import deal_identification_a
from handlers.deal_identification_b import deal_identification_b
from handlers.deal_version import deal_version
from handlers.deal_hmipro_version import deal_hmipro_version
from handlers.deal_get_machine import deal_get_machine
from handlers.deal_get_moldset import deal_get_moldset
from handlers.deal_online_status import deal_online_status
from handlers.deal_line_status import deal_line_status
from handlers.deal_get_user import deal_get_user

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# Server Configuration
UDP_IP = "0.0.0.0"
UDP_PORT = 12345
METRICS_PORT = 8000

# Protocol IDs
PID_TEMPERATURE      = 0x10000
PID_MONITOR          = 0x10001
PID_UPDATE           = 0x10003
PID_HMI_BOUND        = 0x20000
PID_ERROR            = 0x20001
PID_ENERGY           = 0x20006
PID_MACHINE_STATUS   = 0x40000
PID_INFERIOR_STATUS  = 0x40003
PID_XML              = 0x1000004
PID_IDENTIFICATION_A = 0x100000a
PID_IDENTIFICATION_B = 0x100000b
PID_VERSION          = 0x1010000
PID_HMIPRO_VERSION   = 0x1010002
PID_GET_MACHINE      = 0x1020000
PID_GET_MOLDSET      = 0x1020001
PID_ONLINE_STATUS    = 0x2000000
PID_LINE_STATUS      = 0x2000001
PID_GET_USER         = 0x2000002

# MAC Address to Human Readable Name Mapping
MAC_TO_NAME = {
    'd4:e9:5e:16:e2:2c': 'mesin10'
}

class MachineContext(dict):
    def __init__(self, ip, mac_mapping, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip = ip
        self.mac = None
        self.mac_mapping = mac_mapping

    @property
    def machine_label(self):
        # Normalize MAC to lowercase for lookup if present
        if self.mac:
            mac_norm = self.mac.lower()
            if mac_norm in self.mac_mapping:
                return self.mac_mapping[mac_norm]
        return self.ip

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        update_metric(self.machine_label, self.ip, key, value)

class MockSocket:
    def sendto(self, data, addr):
        print(binascii.hexlify(data).decode('ascii'))
        sys.stdout.flush()

class IndustrialMachineServer:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.ip, self.port))
        
        self.machines = {} 
        self._current_context = None
        self.moldset_chunks = {} 
        self.running = True
        self.mac_mapping = MAC_TO_NAME
        
        self.handlers = {
            PID_TEMPERATURE:      deal_temperature,
            PID_MONITOR:          deal_monitor,
            PID_UPDATE:           deal_update,
            PID_HMI_BOUND:        deal_hmi_bound,
            PID_ERROR:            deal_error,
            PID_ENERGY:           deal_energy,
            PID_MACHINE_STATUS:   deal_machine_status,
            PID_INFERIOR_STATUS:  deal_inferior_status,
            PID_XML:              deal_xml,
            PID_IDENTIFICATION_A: deal_identification_a,
            PID_IDENTIFICATION_B: deal_identification_b,
            PID_VERSION:          deal_version,
            PID_HMIPRO_VERSION:   deal_hmipro_version,
            PID_GET_MACHINE:      deal_get_machine,
            PID_GET_MOLDSET:      deal_get_moldset,
            PID_ONLINE_STATUS:    deal_online_status,
            PID_LINE_STATUS:      deal_line_status,
            PID_GET_USER:         deal_get_user,
        }

    @property
    def data_store(self):
        if self._current_context is None:
            return {} 
        return self._current_context

    def parse_protocol_id(self, data):
        if len(data) < 16:
            return None
        raw_pid = struct.unpack_from('<I', data, 12)[0]
        return raw_pid & 0x3FFFFFFF

    def process_packet(self, data, addr):
        client_ip = addr[0]
        if client_ip not in self.machines:
            self.machines[client_ip] = MachineContext(client_ip, self.mac_mapping)
        self._current_context = self.machines[client_ip]

        pid = self.parse_protocol_id(data)
        if pid is None:
            return

        if pid in self.handlers:
            # Standardized call: (server, addr, data)
            handler = self.handlers[pid]
            PACKET_COUNT.labels(handler=handler.__name__).inc()
            handler(self, addr, data)

    def shutdown(self, signum, frame):
        logger.info(f"Received signal {signum}, stopping server...")
        self.running = False

    def start(self):
        logger.info(f"Starting Prometheus Metrics on port {METRICS_PORT}")
        start_http_server(METRICS_PORT)
        logger.info(f"Server listening on {self.ip}:{self.port} (UDP)")
        
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)
        
        self.sock.settimeout(1.0)
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(8192)
                self.process_packet(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error handling packet: {e}")
        
        logger.info("Server stopped.")

    def run_interactive_mode(self):
        self.sock = MockSocket()
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = binascii.unhexlify(line)
                    addr = ('127.0.0.1', 12345)
                    self.process_packet(data, addr)
                except Exception as e:
                    # logger.error(f"Error processing line: {e}")
                    pass
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    pass
