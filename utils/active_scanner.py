#!/usr/bin/env python3
"""
Active Network Scanner for IoTSentinel

Uses nmap for active network scanning and host discovery.
Requires root/sudo privileges for full functionality.
"""

import logging
import os
from typing import Dict, Any, Optional, List, Callable
import nmap

logger = logging.getLogger(__name__)


class ActiveScanner:
    """
    Active network scanner using nmap.

    Provides host discovery and service detection capabilities.
    Gracefully degrades if insufficient privileges.
    """

    def __init__(
        self,
        on_device_discovered: Optional[Callable] = None,
        check_privileges: bool = True
    ):
        """
        Initialize active scanner.

        Args:
            on_device_discovered: Callback for device discovery
            check_privileges: Whether to check for root privileges
        """
        self.on_device_discovered = on_device_discovered
        self.nm = nmap.PortScanner()

        # Check if nmap is available
        self.nmap_available = self._check_nmap()

        # Check privileges
        self.has_root = False
        if check_privileges:
            self.has_root = self._check_root_privileges()

        if not self.nmap_available:
            logger.warning("nmap not found - active scanning disabled")
        elif not self.has_root:
            logger.warning("Running without root privileges - some scan types will be limited")
        else:
            logger.info("Active scanner initialized with full capabilities")

    def _check_nmap(self) -> bool:
        """
        Check if nmap is installed and accessible.

        Returns:
            True if nmap is available
        """
        try:
            self.nm.nmap_version()
            return True
        except Exception as e:
            logger.error(f"nmap not available: {e}")
            return False

    def _check_root_privileges(self) -> bool:
        """
        Check if running with root privileges.

        Returns:
            True if root/sudo
        """
        try:
            is_root = os.geteuid() == 0
            if is_root:
                logger.info("Running with root privileges")
            else:
                logger.warning("Not running as root - using limited scan types")
            return is_root
        except AttributeError:
            # Windows doesn't have geteuid
            return False

    def scan_network(
        self,
        network: str,
        scan_type: str = 'ping',
        timeout: int = 300
    ) -> List[Dict[str, Any]]:
        """
        Scan network for devices.

        Args:
            network: Network CIDR (e.g., "192.168.1.0/24")
            scan_type: Type of scan:
                - 'ping': Host discovery only (fast)
                - 'services': Service/port scanning (slow)
                - 'os': OS detection (requires root, very slow)
            timeout: Scan timeout in seconds

        Returns:
            List of discovered devices
        """
        if not self.nmap_available:
            logger.error("nmap not available")
            return []

        logger.info(f"Starting {scan_type} scan of {network}")

        try:
            # Select scan arguments based on type and privileges
            if scan_type == 'ping':
                if self.has_root:
                    # SYN ping (requires root, faster)
                    arguments = '-sn -PS22,80,443'
                else:
                    # TCP connect ping (no root required)
                    arguments = '-sn -Pn'

            elif scan_type == 'services':
                if self.has_root:
                    # SYN scan (requires root, faster)
                    arguments = '-sS -p 22,80,443,554,8000,8080,8443,9000 --open'
                else:
                    # TCP connect scan (no root required, slower)
                    arguments = '-sT -p 22,80,443,554,8000,8080,8443,9000 --open'

            elif scan_type == 'os':
                if not self.has_root:
                    logger.warning("OS detection requires root privileges, falling back to service scan")
                    return self.scan_network(network, 'services', timeout)
                arguments = '-O -sV --osscan-guess'

            else:
                logger.error(f"Unknown scan type: {scan_type}")
                return []

            # Add timeout
            arguments += f' --host-timeout {timeout}s'

            # Perform scan
            self.nm.scan(hosts=network, arguments=arguments)

            # Process results
            discovered = []
            for host in self.nm.all_hosts():
                device_info = self._process_scan_result(host, scan_type)
                if device_info:
                    discovered.append(device_info)

                    # Notify callback
                    if self.on_device_discovered:
                        try:
                            self.on_device_discovered(device_info)
                        except Exception as e:
                            logger.error(f"Error in discovery callback: {e}")

            logger.info(f"Scan complete, found {len(discovered)} devices")
            return discovered

        except Exception as e:
            logger.error(f"Error during network scan: {e}")
            return []

    def _process_scan_result(
        self,
        host: str,
        scan_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Process nmap scan result for a single host.

        Args:
            host: Host IP address
            scan_type: Type of scan performed

        Returns:
            Device information dictionary or None
        """
        try:
            host_info = self.nm[host]

            # Check if host is up
            if host_info.state() != 'up':
                return None

            # Build device info
            device_info = {
                'ip_address': host,
                'state': host_info.state(),
                'discovery_method': f'nmap_{scan_type}'
            }

            # Extract hostname
            hostnames = host_info.hostnames()
            if hostnames:
                device_info['hostname'] = hostnames[0]['name'] if isinstance(hostnames[0], dict) else hostnames[0]
            else:
                device_info['hostname'] = host

            # Extract MAC address and vendor
            if 'mac' in host_info['addresses']:
                device_info['mac_address'] = host_info['addresses']['mac']

                # Try to get vendor from nmap
                if 'vendor' in host_info and host_info['vendor']:
                    for mac, vendor in host_info['vendor'].items():
                        device_info['vendor'] = vendor
                        break

            # Extract open ports (for service scans)
            if 'tcp' in host_info:
                open_ports = []
                for port, port_info in host_info['tcp'].items():
                    if port_info['state'] == 'open':
                        open_ports.append(port)
                device_info['open_ports'] = open_ports

                # Extract service information
                services = []
                for port, port_info in host_info['tcp'].items():
                    if port_info['state'] == 'open':
                        service = {
                            'port': port,
                            'name': port_info.get('name', ''),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', '')
                        }
                        services.append(service)
                device_info['services'] = services

            # Extract OS information (for OS scans)
            if 'osmatch' in host_info:
                os_matches = host_info['osmatch']
                if os_matches:
                    best_match = os_matches[0]
                    device_info['os'] = best_match.get('name', '')
                    device_info['os_accuracy'] = best_match.get('accuracy', 0)

            logger.debug(f"Processed scan result for {host}: {device_info.get('hostname')}")
            return device_info

        except Exception as e:
            logger.error(f"Error processing scan result for {host}: {e}")
            return None

    def scan_single_host(
        self,
        host: str,
        scan_ports: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Perform detailed scan of a single host.

        Args:
            host: IP address or hostname
            scan_ports: Ports to scan (e.g., "22,80,443" or "1-1000")
                       None = common ports

        Returns:
            Device information dictionary or None
        """
        if not self.nmap_available:
            logger.error("nmap not available")
            return None

        logger.info(f"Scanning single host: {host}")

        try:
            # Use common ports if not specified
            if scan_ports is None:
                scan_ports = '21,22,23,80,443,554,8000,8008,8080,8443,9000'

            # Select scan type based on privileges
            if self.has_root:
                arguments = f'-sS -sV -p {scan_ports} --open'
            else:
                arguments = f'-sT -p {scan_ports} --open'

            # Perform scan
            self.nm.scan(hosts=host, arguments=arguments)

            # Process result
            if host in self.nm.all_hosts():
                return self._process_scan_result(host, 'detailed')
            else:
                logger.warning(f"Host {host} not found in scan results")
                return None

        except Exception as e:
            logger.error(f"Error scanning host {host}: {e}")
            return None

    def quick_ping_scan(self, network: str) -> List[str]:
        """
        Quick ping scan to find live hosts.

        Args:
            network: Network CIDR

        Returns:
            List of IP addresses of live hosts
        """
        if not self.nmap_available:
            return []

        logger.info(f"Quick ping scan of {network}")

        try:
            # Use fast ping scan
            arguments = '-sn -T4'
            self.nm.scan(hosts=network, arguments=arguments)

            # Return list of live hosts
            hosts = [host for host in self.nm.all_hosts() if self.nm[host].state() == 'up']

            logger.info(f"Found {len(hosts)} live hosts")
            return hosts

        except Exception as e:
            logger.error(f"Error in quick ping scan: {e}")
            return []

    def get_capabilities(self) -> Dict[str, bool]:
        """
        Get scanner capabilities.

        Returns:
            Dictionary with capability flags
        """
        return {
            'nmap_available': self.nmap_available,
            'has_root': self.has_root,
            'can_syn_scan': self.has_root,
            'can_os_detect': self.has_root,
            'can_ping_scan': True,
            'can_service_scan': self.nmap_available
        }


# Global active scanner instance
_active_scanner = None


def get_active_scanner(
    on_device_discovered: Optional[Callable] = None
) -> ActiveScanner:
    """
    Get global active scanner instance.

    Args:
        on_device_discovered: Callback for device discovery

    Returns:
        ActiveScanner instance
    """
    global _active_scanner
    if _active_scanner is None:
        _active_scanner = ActiveScanner(on_device_discovered=on_device_discovered)
    return _active_scanner
