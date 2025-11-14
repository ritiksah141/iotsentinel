#!/usr/bin/env python3
"""
Firewall Manager for IoTSentinel

Connects to an SSH-accessible router (e.g., OpenWrt)
and manages firewall rules to block untrusted devices.
"""

import logging
import sys
from pathlib import Path
import paramiko

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# WARNING: These are example commands for OpenWrt's `iptables`.
# They may need to be adapted for your specific router firmware.
IPTABLES_CHAIN = "IoTSentinel"

def get_ssh_client():
    """Create and return an SSH client connected to the router."""
    if not config.get('firewall', 'enabled', default=False):
        logger.warning("Firewall management is disabled in the config.")
        return None

    router_ip = config.get('firewall', 'router_ip')
    router_user = config.get('firewall', 'router_user')
    router_password = config.get('firewall', 'router_password')

    if not all([router_ip, router_user, router_password]):
        logger.error("Firewall configuration is incomplete.")
        return None

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(router_ip, username=router_user, password=router_password, timeout=10)
        logger.info(f"SSH connection successful to {router_ip}")
        return client
    except Exception as e:
        logger.error(f"SSH connection failed: {e}")
        return None

def apply_rules(trusted_mac_addresses: list):
    """
    Apply firewall rules to only allow trusted devices.

    Args:
        trusted_mac_addresses: A list of MAC addresses to allow.
    """
    client = get_ssh_client()
    if not client:
        return

    try:
        # 1. Create a new chain for our rules
        client.exec_command(f"iptables -N {IPTABLES_CHAIN}")
        client.exec_command(f"iptables -F {IPTABLES_CHAIN}") # Flush existing rules in our chain

        # 2. Hardcoded safety rules (allow IoTSentinel and router)
        # Note: You might need to get the MAC address of the Pi and router dynamically
        # For now, we assume they are not blocked by the final rule.

        # 3. Add rules for each trusted MAC address
        for mac in trusted_mac_addresses:
            if mac: # Ensure MAC is not empty
                logger.info(f"Allowing MAC: {mac}")
                client.exec_command(f"iptables -A {IPTABLES_CHAIN} -m mac --mac-source {mac} -j ACCEPT")

        # 4. Add a rule to drop all other traffic in our chain
        client.exec_command(f"iptables -A {IPTABLES_CHAIN} -j DROP")
        
        # 5. Insert our chain at the top of the FORWARD chain
        # This ensures our rules are checked first.
        client.exec_command(f"iptables -I FORWARD 1 -j {IPTABLES_CHAIN}")

        logger.info("Firewall rules applied successfully.")

    except Exception as e:
        logger.error(f"Error applying firewall rules: {e}")
    finally:
        client.close()

def clear_rules():
    """Remove all firewall rules managed by IoTSentinel."""
    client = get_ssh_client()
    if not client:
        return

    try:
        # 1. Remove our chain from the FORWARD chain
        client.exec_command(f"iptables -D FORWARD -j {IPTABLES_CHAIN}")

        # 2. Flush our custom chain
        client.exec_command(f"iptables -F {IPTABLES_CHAIN}")

        # 3. Delete our custom chain
        client.exec_command(f"iptables -X {IPTABLES_CHAIN}")

        logger.info("Firewall rules cleared successfully.")

    except Exception as e:
        logger.error(f"Error clearing firewall rules: {e}")
    finally:
        client.close()

if __name__ == '__main__':
    # Example usage (for testing)
    import argparse
    parser = argparse.ArgumentParser(description="IoTSentinel Firewall Manager")
    parser.add_argument('--apply', nargs='+', help='List of trusted MAC addresses to apply')
    parser.add_argument('--clear', action='store_true', help='Clear all rules')
    
    args = parser.parse_args()
    
    if args.apply:
        print(f"Applying rules for: {args.apply}")
        apply_rules(args.apply)
    elif args.clear:
        print("Clearing all rules...")
        clear_rules()
    else:
        print("Use --apply [MACs...] or --clear")
