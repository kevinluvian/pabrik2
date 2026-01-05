import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger(__name__)

PRECISION_MAP = {}

def load_precision_map(file_path="tmscada/MoldData_54_52.xml"):
    """
    Parses the MoldData XML to extract the precision for each parameter.
    Precision determines the divisor.
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        for item in root.findall('iNetData'):
            name_elem = item.find('Name')
            precision_elem = item.find('MoldSetPrecision54') # Using 54 as the standard
            
            if name_elem is not None and precision_elem is not None:
                name = name_elem.text
                try:
                    precision = int(precision_elem.text)
                    
                    divisor = 1.0
                    
                    # Refined mapping based on analysis
                    if precision == 1:
                        divisor = 1.0
                    elif precision == 10:
                        divisor = 10.0
                    elif precision == 11:
                        divisor = 10.0 # Speed 550 -> 55.0
                    elif precision == 2:
                        divisor = 100.0
                    elif precision == 3:
                        divisor = 1000.0
                    elif precision == 4:
                        divisor = 10000.0
                    elif precision == 5:
                        divisor = 100000.0
                    elif precision in [100, 101]:
                        divisor = 100.0
                        
                    PRECISION_MAP[name] = divisor
                except (ValueError, TypeError):
                    continue
        logger.info(f"Loaded {len(PRECISION_MAP)} parameter precisions from {file_path}")

    except FileNotFoundError:
        logger.error(f"Precision map file not found: {file_path}. Floats will not be scaled.")
    except Exception as e:
        logger.error(f"Error parsing precision map: {e}")

def get_divisor(key):
    return PRECISION_MAP.get(key, 1.0)

# Load on startup
load_precision_map()
