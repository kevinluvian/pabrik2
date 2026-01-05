import logging
import re

logger = logging.getLogger(__name__)

def deal_xml(server, client_addr, data):
    """
    Handles PID 0x1000004: XML Data Exchange
    Parses versioning info from XML payload to stay in sync with HMI.
    """
    payload = data[16:]
    if not payload:
        return

    try:
        xml_text = payload.decode('utf-8', errors='ignore').strip('\x00')
        server.data_store['LastXML'] = xml_text
        
        # Simple regex to mimic GetXml/parseBlackList version extraction
        version_match = re.search(r'<Version>(.*?)</Version>', xml_text)
        if version_match:
            version = version_match.group(1)
            server.data_store['MappingVersion'] = version
            logger.info(f"Received XML Config. Version: {version}")
            
    except Exception as e:
        logger.error(f"Error processing XML payload: {e}")

    # No response sent (Silent Handler)
