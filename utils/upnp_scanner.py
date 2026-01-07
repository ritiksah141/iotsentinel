#!/usr/bin/env python3
"""
UPnP/SSDP Scanner for IoTSentinel

Discovers UPnP devices using SSDP (Simple Service Discovery Protocol).
Supports both passive listening and active M-SEARCH queries.
"""

import logging
import socket
import struct
import threading
import time
import requests
from typing import Dict, Any, Optional, List, Callable
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


# SSDP multicast address and port
SSDP_MULTICAST_ADDR = '239.255.255.250'
SSDP_PORT = 1900

# M-SEARCH query template
MSEARCH_TEMPLATE = """M-SEARCH * HTTP/1.1
HOST: {host}:{port}
MAN: "ssdp:discover"
MX: {mx}
ST: {st}
USER-AGENT: IoTSentinel/1.0

"""

# Common search targets for IoT devices
SEARCH_TARGETS = [
    'ssdp:all',                          # All UPnP devices
    'upnp:rootdevice',                   # Root devices
    'urn:schemas-upnp-org:device:Basic:1', # Basic devices
    'urn:schemas-upnp-org:device:MediaRenderer:1', # Media renderers (TVs, speakers)
    'urn:schemas-upnp-org:device:MediaServer:1',   # Media servers (NAS)
]


class UPnPScanner:
    """
    UPnP device scanner using SSDP protocol.

    Supports both passive listening and active M-SEARCH queries.
    """

    def __init__(
        self,
        on_device_discovered: Optional[Callable] = None,
        fetch_device_xml: bool = True
    ):
        """
        Initialize UPnP scanner.

        Args:
            on_device_discovered: Callback function for device discovery
            fetch_device_xml: Whether to fetch device description XML
        """
        self.on_device_discovered = on_device_discovered
        self.fetch_device_xml = fetch_device_xml

        self.discovered_devices = {}  # location_url -> device_info
        self.lock = threading.Lock()

        self.passive_socket = None
        self.passive_thread = None
        self.running = False

        logger.info("UPnP scanner initialized")

    def start_passive_listener(self):
        """Start passive SSDP listener to detect UPnP announcements."""
        if self.running:
            logger.warning("UPnP passive listener already running")
            return

        try:
            # Create socket for multicast
            self.passive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.passive_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind to SSDP port
            self.passive_socket.bind(('', SSDP_PORT))

            # Join multicast group
            mreq = struct.pack('4sl', socket.inet_aton(SSDP_MULTICAST_ADDR), socket.INADDR_ANY)
            self.passive_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            # Set timeout for clean shutdown
            self.passive_socket.settimeout(2.0)

            # Start listener thread
            self.running = True
            self.passive_thread = threading.Thread(
                target=self._passive_listener_loop,
                name="UPnP-PassiveListener",
                daemon=True
            )
            self.passive_thread.start()

            logger.info("UPnP passive listener started")

        except Exception as e:
            logger.error(f"Error starting UPnP passive listener: {e}")
            self.stop_passive_listener()

    def stop_passive_listener(self):
        """Stop passive SSDP listener."""
        if not self.running:
            return

        logger.info("Stopping UPnP passive listener...")
        self.running = False

        if self.passive_thread:
            self.passive_thread.join(timeout=5.0)
            self.passive_thread = None

        if self.passive_socket:
            try:
                self.passive_socket.close()
            except Exception as e:
                logger.warning(f"Error closing socket: {e}")
            self.passive_socket = None

        logger.info("UPnP passive listener stopped")

    def _passive_listener_loop(self):
        """Background loop for passive SSDP listening."""
        logger.info("UPnP passive listener loop started")

        while self.running:
            try:
                # Receive SSDP message
                data, addr = self.passive_socket.recvfrom(65507)

                # Parse SSDP message
                self._process_ssdp_message(data.decode('utf-8', errors='ignore'), addr[0])

            except socket.timeout:
                # Timeout is expected for clean shutdown
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error in passive listener: {e}")
                    time.sleep(1)

        logger.info("UPnP passive listener loop stopped")

    def active_scan(
        self,
        search_targets: Optional[List[str]] = None,
        mx: int = 2,
        timeout: float = 5.0
    ) -> List[Dict[str, Any]]:
        """
        Perform active UPnP M-SEARCH scan.

        Args:
            search_targets: List of search targets (None = default targets)
            mx: Maximum wait time in seconds (1-5)
            timeout: Total scan timeout in seconds

        Returns:
            List of discovered devices
        """
        search_targets = search_targets or SEARCH_TARGETS
        discovered = []

        logger.info(f"Starting active UPnP scan with {len(search_targets)} targets")

        for st in search_targets:
            try:
                devices = self._msearch(st, mx, timeout)
                discovered.extend(devices)
            except Exception as e:
                logger.error(f"Error scanning for {st}: {e}")

        logger.info(f"Active UPnP scan complete, found {len(discovered)} devices")
        return discovered

    def _msearch(
        self,
        search_target: str,
        mx: int = 2,
        timeout: float = 5.0
    ) -> List[Dict[str, Any]]:
        """
        Send M-SEARCH query and collect responses.

        Args:
            search_target: SSDP search target
            mx: Maximum wait time
            timeout: Response collection timeout

        Returns:
            List of device information dictionaries
        """
        # Build M-SEARCH request
        msg = MSEARCH_TEMPLATE.format(
            host=SSDP_MULTICAST_ADDR,
            port=SSDP_PORT,
            mx=mx,
            st=search_target
        )

        discovered = []

        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(timeout)

            # Send M-SEARCH
            sock.sendto(msg.encode('utf-8'), (SSDP_MULTICAST_ADDR, SSDP_PORT))

            # Collect responses
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(65507)
                    device_info = self._process_ssdp_message(
                        data.decode('utf-8', errors='ignore'),
                        addr[0]
                    )
                    if device_info:
                        discovered.append(device_info)
                except socket.timeout:
                    break
                except Exception as e:
                    logger.warning(f"Error receiving M-SEARCH response: {e}")

            sock.close()

        except Exception as e:
            logger.error(f"Error in M-SEARCH: {e}")

        return discovered

    def _process_ssdp_message(self, message: str, source_ip: str) -> Optional[Dict[str, Any]]:
        """
        Parse SSDP message and extract device information.

        Args:
            message: SSDP message text
            source_ip: Source IP address

        Returns:
            Device information dictionary or None
        """
        try:
            lines = message.split('\r\n')
            headers = {}

            # Parse headers
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            # Extract location URL
            location = headers.get('location')
            if not location:
                return None

            # Check if already discovered
            with self.lock:
                if location in self.discovered_devices:
                    return None

            # Extract basic info
            device_info = {
                'ip_address': source_ip,
                'location': location,
                'server': headers.get('server', ''),
                'st': headers.get('st', ''),  # Search target
                'usn': headers.get('usn', ''),  # Unique Service Name
                'discovery_method': 'upnp'
            }

            # Fetch device description XML if enabled
            if self.fetch_device_xml:
                xml_info = self._fetch_device_description(location)
                if xml_info:
                    device_info.update(xml_info)

            # Store discovered device
            with self.lock:
                self.discovered_devices[location] = device_info

            # Notify callback
            if self.on_device_discovered:
                try:
                    self.on_device_discovered(device_info)
                except Exception as e:
                    logger.error(f"Error in discovery callback: {e}")

            logger.info(f"Discovered UPnP device: {device_info.get('friendly_name', source_ip)} at {source_ip}")
            return device_info

        except Exception as e:
            logger.error(f"Error processing SSDP message: {e}")
            return None

    def _fetch_device_description(self, location_url: str) -> Optional[Dict[str, Any]]:
        """
        Fetch and parse device description XML.

        Args:
            location_url: URL to device description XML

        Returns:
            Dictionary with device info from XML
        """
        try:
            # Fetch XML with timeout
            response = requests.get(location_url, timeout=5)
            response.raise_for_status()

            # Parse XML
            root = ET.fromstring(response.content)

            # Define XML namespaces
            ns = {'upnp': 'urn:schemas-upnp-org:device-1-0'}

            # Try with namespace
            device = root.find('.//upnp:device', ns)
            if device is None:
                # Try without namespace
                device = root.find('.//device')

            if device is None:
                logger.warning(f"Could not find device element in XML from {location_url}")
                return None

            # Extract device information
            info = {}

            # Helper to get text from element
            def get_text(element, tag, namespaces=None):
                elem = element.find(tag, namespaces) if namespaces else element.find(tag)
                return elem.text if elem is not None else ''

            info['friendly_name'] = get_text(device, 'upnp:friendlyName', ns) or get_text(device, 'friendlyName')
            info['manufacturer'] = get_text(device, 'upnp:manufacturer', ns) or get_text(device, 'manufacturer')
            info['model'] = get_text(device, 'upnp:modelName', ns) or get_text(device, 'modelName')
            info['model_number'] = get_text(device, 'upnp:modelNumber', ns) or get_text(device, 'modelNumber')
            info['device_type'] = get_text(device, 'upnp:deviceType', ns) or get_text(device, 'deviceType')
            info['hostname'] = info['friendly_name'] or 'unknown'

            # Classify device type
            device_type_str = info.get('device_type', '').lower()
            if 'mediarenderer' in device_type_str:
                info['category'] = 'entertainment'
                info['icon'] = '📺'
            elif 'mediaserver' in device_type_str:
                info['category'] = 'entertainment'
                info['icon'] = '💾'
            else:
                info['category'] = 'other'
                info['icon'] = '📱'

            return info

        except requests.RequestException as e:
            logger.warning(f"Could not fetch device description from {location_url}: {e}")
            return None
        except ET.ParseError as e:
            logger.warning(f"Could not parse device description XML: {e}")
            return None
        except Exception as e:
            logger.error(f"Error fetching device description: {e}")
            return None

    def get_discovered_devices(self) -> List[Dict[str, Any]]:
        """
        Get all discovered devices.

        Returns:
            List of device information dictionaries
        """
        with self.lock:
            return list(self.discovered_devices.values())

    def get_stats(self) -> Dict[str, Any]:
        """
        Get scanner statistics.

        Returns:
            Dictionary with stats
        """
        with self.lock:
            total_devices = len(self.discovered_devices)

        return {
            'total_devices': total_devices,
            'passive_listener_running': self.running
        }


# Global UPnP scanner instance
_upnp_scanner = None


def get_upnp_scanner(
    on_device_discovered: Optional[Callable] = None
) -> UPnPScanner:
    """
    Get global UPnP scanner instance.

    Args:
        on_device_discovered: Callback for device discovery

    Returns:
        UPnPScanner instance
    """
    global _upnp_scanner
    if _upnp_scanner is None:
        _upnp_scanner = UPnPScanner(on_device_discovered=on_device_discovered)
    return _upnp_scanner
