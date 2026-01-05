from tmscada_implementation import IndustrialMachineServer
import sys

# Server Configuration
UDP_IP = "0.0.0.0"
UDP_PORT = 12345

if __name__ == "__main__":
    # Check for interactive mode
    interactive = False
    if len(sys.argv) > 1 and (sys.argv[1] == '--interactive' or sys.argv[1] == '-i'):
        interactive = True

    server = IndustrialMachineServer(UDP_IP, UDP_PORT)
    
    if interactive:
        server.run_interactive_mode()
    else:
        server.start()