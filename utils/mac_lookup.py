#!/usr/bin/env python3
"""
MAC Address Manufacturer Lookup

Uses the manuf library for OUI (Organizationally Unique Identifier) lookup.
Includes fallback database and detection of randomized MAC addresses.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Try to import manuf library
try:
    from manuf import manuf
    # Initialize the MAC address parser
    p = manuf.MacParser(update=False)
    MANUF_AVAILABLE = True
except ImportError:
    MANUF_AVAILABLE = False
    p = None
    logger.warning("manuf library not available. Install with: pip install manuf")


def get_manufacturer(mac_address: Optional[str]) -> str:
    """
    Get manufacturer name from MAC address.

    Args:
        mac_address: MAC address in any common format (AA:BB:CC:DD:EE:FF)

    Returns:
        Manufacturer name or "Unknown"
    """
    if not mac_address:
        return "Unknown"

    # Clean up MAC address
    mac_clean = mac_address.strip().upper()

    # Check for randomized/private MAC addresses
    # Randomized MACs have bit 1 of first octet set (locally administered)
    try:
        first_octet = int(mac_clean.split(':')[0], 16)
        if first_octet & 0x02:  # Check if locally administered bit is set
            return "Private/Random MAC"
    except (ValueError, IndexError):
        pass

    # Try manuf library first
    if MANUF_AVAILABLE and p:
        try:
            manufacturer = p.get_manuf(mac_address)
            if manufacturer:
                return manufacturer
        except Exception as e:
            logger.debug(f"Error looking up MAC {mac_address}: {e}")

    # Fallback: Check common manufacturers by OUI prefix
    oui_database = {
        '60:8D:26': 'Arcadyan',
        '44:3D:54': 'Samsung Electronics',
        '00:50:56': 'VMware',
        'DC:A6:32': 'Raspberry Pi Trading',
        'B8:27:EB': 'Raspberry Pi Foundation',
        'E4:5F:01': 'Raspberry Pi Trading',
        '28:CD:C1': 'Raspberry Pi Trading',
        'D8:3A:DD': 'Raspberry Pi Trading',
        '00:1B:44': 'Raspberry Pi Foundation',
        '00:0C:29': 'VMware',
        '00:05:69': 'VMware',
        '00:0A:95': 'Apple',
        '00:14:51': 'Apple',
        '00:16:CB': 'Apple',
        '00:17:F2': 'Apple',
        '00:19:E3': 'Apple',
        '00:1B:63': 'Apple',
        '00:1C:B3': 'Apple',
        '00:1D:4F': 'Apple',
        '00:1E:52': 'Apple',
        '00:1F:5B': 'Apple',
        '00:21:E9': 'Apple',
        '00:22:41': 'Apple',
        '00:23:12': 'Apple',
        '00:23:32': 'Apple',
        '00:23:6C': 'Apple',
        '00:23:DF': 'Apple',
        '00:24:36': 'Apple',
        '00:25:00': 'Apple',
        '00:25:4B': 'Apple',
        '00:25:BC': 'Apple',
        '00:26:08': 'Apple',
        '00:26:4A': 'Apple',
        '00:26:B0': 'Apple',
        '00:26:BB': 'Apple',
        '3C:15:C2': 'Apple',
        '08:00:27': 'VirtualBox',
        '52:54:00': 'QEMU/KVM',
        'AC:DE:48': 'Apple',
        '00:CD:FE': 'Apple',
        'F0:18:98': 'Apple',
        '78:CA:39': 'Apple',
        'A4:83:E7': 'Apple',
        'B4:F0:AB': 'Apple',
        '54:26:96': 'Apple',
        '68:5B:35': 'Apple',
        'C8:2A:14': 'Apple',
        '10:DD:B1': 'Apple',
        '7C:11:BE': 'Apple',
        '34:36:3B': 'Apple',
        '8C:85:90': 'Apple',
        '40:B3:95': 'Apple',
        '00:88:65': 'Apple',
        '90:3C:92': 'Apple',
        '28:CF:E9': 'Apple',
    }

    # Extract OUI (first 3 octets)
    try:
        oui = ':'.join(mac_clean.split(':')[:3])
        if oui in oui_database:
            return oui_database[oui]
    except Exception as e:
        logger.debug(f"Error extracting OUI from {mac_address}: {e}")

    return "Unknown"


def update_manuf_database():
    """Update the manuf database to latest version."""
    if not MANUF_AVAILABLE:
        print("manuf library not installed. Install with: pip install manuf")
        return False

    try:
        print("Updating MAC vendor database...")
        p_update = manuf.MacParser(update=True)
        print("✓ MAC vendor database updated successfully!")
        return True
    except Exception as e:
        print(f"Error updating database: {e}")
        return False


# Example usage
if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == '--update':
        update_manuf_database()
    else:
        # Test with your actual MACs
        test_macs = [
            '60:8d:26:51:b1:2d',
            '44:3d:54:f8:ae:37',
            '82:76:bc:aa:67:e9',
            '0a:ae:e1:15:32:af',
            'DC:A6:32:12:34:56',
        ]

        print("\nMAC Address Lookup Test:")
        print("=" * 60)
        for mac in test_macs:
            print(f"{mac:<20} → {get_manufacturer(mac)}")
        print("=" * 60)
