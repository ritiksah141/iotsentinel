# utils/mac_lookup.py

from manuf import manuf

# Initialize the MAC address parser.
# The database will be downloaded on first use if `update=True`.
# We set `update=False` to avoid network access during runtime
# and rely on a pre-populated database.
p = manuf.MacParser(update=False)

def get_manufacturer(mac_address):
    """
    Looks up the manufacturer of a given MAC address.

    Args:
        mac_address (str): The MAC address to look up.

    Returns:
        str: The name of the manufacturer, or "Unknown" if not found.
    """
    if not mac_address:
        return "Unknown"
    return p.get_manuf(mac_address) or "Unknown"
