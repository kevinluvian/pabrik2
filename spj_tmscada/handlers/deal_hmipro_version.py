import logging

logger = logging.getLogger(__name__)

def deal_hmipro_version(server, client_addr, data):
    """
    Handles PID 0x1010002: HMI Pro Version Check
    """
    payload = data[16:]
    logger.info(f"Received HMI Pro Version Check (PID 0x1010002), payload len={len(payload)}")
    # Silent handler