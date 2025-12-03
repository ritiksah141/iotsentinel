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
    private_key_path = config.get('firewall', 'router_private_key_path')

    if not all([router_ip, router_user, private_key_path]):
        logger.error("Firewall configuration is incomplete.")
        return None

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key = paramiko.RSAKey.from_private_key_file(private_key_path)
        client.connect(router_ip, username=router_user, pkey=private_key, timeout=10)
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

def block_device(mac_address: str):
    """
    Block a specific device by MAC address.

    Args:
        mac_address: MAC address to block (e.g., "AA:BB:CC:DD:EE:FF")
    """
    client = get_ssh_client()
    if not client:
        logger.error("Cannot block device: SSH client unavailable")
        return False

    try:
        # Ensure our chain exists
        client.exec_command(f"iptables -N {IPTABLES_CHAIN} 2>/dev/null || true")

        # Add DROP rule for this specific MAC address
        command = f"iptables -A {IPTABLES_CHAIN} -m mac --mac-source {mac_address} -j DROP"
        stdin, stdout, stderr = client.exec_command(command)
        error = stderr.read().decode()

        if error and "already exists" not in error.lower():
            logger.error(f"Error blocking MAC {mac_address}: {error}")
            return False

        # Ensure our chain is active in FORWARD chain
        client.exec_command(f"iptables -C FORWARD -j {IPTABLES_CHAIN} 2>/dev/null || iptables -I FORWARD 1 -j {IPTABLES_CHAIN}")

        logger.info(f"Blocked device: {mac_address}")
        return True

    except Exception as e:
        logger.error(f"Exception while blocking device {mac_address}: {e}")
        return False
    finally:
        client.close()

def unblock_device(mac_address: str):
    """
    Unblock a specific device by MAC address.

    Args:
        mac_address: MAC address to unblock
    """
    client = get_ssh_client()
    if not client:
        logger.error("Cannot unblock device: SSH client unavailable")
        return False

    try:
        # Remove the DROP rule for this MAC address
        command = f"iptables -D {IPTABLES_CHAIN} -m mac --mac-source {mac_address} -j DROP"
        stdin, stdout, stderr = client.exec_command(command)
        error = stderr.read().decode()

        if error and "does not exist" not in error.lower():
            logger.error(f"Error unblocking MAC {mac_address}: {error}")
            return False

        logger.info(f"Unblocked device: {mac_address}")
        return True

    except Exception as e:
        logger.error(f"Exception while unblocking device {mac_address}: {e}")
        return False
    finally:
        client.close()

if __name__ == '__main__':
    # Example usage (for testing)
    import argparse
    parser = argparse.ArgumentParser(description="IoTSentinel Firewall Manager")
    parser.add_argument('--apply', nargs='+', help='List of trusted MAC addresses to apply (lockdown mode)')
    parser.add_argument('--clear', action='store_true', help='Clear all rules')
    parser.add_argument('--block', type=str, help='Block a specific MAC address')
    parser.add_argument('--unblock', type=str, help='Unblock a specific MAC address')

    args = parser.parse_args()

    if args.apply:
        print(f"Applying lockdown rules for: {args.apply}")
        apply_rules(args.apply)
    elif args.clear:
        print("Clearing all rules...")
        clear_rules()
    elif args.block:
        print(f"Blocking device: {args.block}")
        success = block_device(args.block)
        sys.exit(0 if success else 1)
    elif args.unblock:
        print(f"Unblocking device: {args.unblock}")
        success = unblock_device(args.unblock)
        sys.exit(0 if success else 1)
    else:
        print("Use --apply [MACs...], --clear, --block [MAC], or --unblock [MAC]")
