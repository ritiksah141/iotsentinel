#!/usr/bin/env python3
"""
mDNS/Zeroconf Listener for IoTSentinel

Passive discovery of IoT devices using mDNS/Bonjour service advertisements.
Listens for common IoT service types and auto-provisions discovered devices.
"""

import logging
import socket
from typing import Dict, Any, Optional, List, Callable
from zeroconf import ServiceBrowser, ServiceListener, Zeroconf, ServiceInfo
import threading
import time

logger = logging.getLogger(__name__)


# Common IoT service types to monitor
IOT_SERVICE_TYPES = [
    "_http._tcp.local.",           # Generic HTTP services
    "_https._tcp.local.",          # Generic HTTPS services
    "_googlecast._tcp.local.",     # Chromecast
    "_airplay._tcp.local.",        # AirPlay (Apple TV, HomePod)
    "_hap._tcp.local.",            # HomeKit Accessory Protocol
    "_homekit._tcp.local.",        # HomeKit
    "_philips-hue._tcp.local.",    # Philips Hue
    "_spotify-connect._tcp.local.", # Spotify Connect
    "_raop._tcp.local.",           # AirPort Express
    "_ipp._tcp.local.",            # Internet Printing Protocol
    "_printer._tcp.local.",        # Network printers
    "_scanner._tcp.local.",        # Network scanners
]


class MDNSListener(ServiceListener):
    """
    Listens for mDNS/Zeroconf service advertisements.

    Passively monitors for IoT device announcements on the network.
    """

    def __init__(self, on_device_discovered: Optional[Callable] = None):
        """
        Initialize mDNS listener.

        Args:
            on_device_discovered: Callback function called when device discovered
                                 Signature: callback(device_info: Dict[str, Any])
        """
        self.on_device_discovered = on_device_discovered
        self.discovered_services = {}  # service_name -> service_info
        self.lock = threading.Lock()

        logger.info("mDNS listener initialized")

    def add_service(self, zc: Zeroconf, service_type: str, name: str):
        """
        Called when a new service is discovered.

        Args:
            zc: Zeroconf instance
            service_type: Type of service (e.g., "_http._tcp.local.")
            name: Service name
        """
        logger.debug(f"mDNS service detected: {name} ({service_type})")

        try:
            # Get detailed service information
            info = zc.get_service_info(service_type, name)

            if info:
                self._process_service(info, service_type)
            else:
                logger.warning(f"Could not get info for service: {name}")

        except Exception as e:
            logger.error(f"Error processing mDNS service {name}: {e}")

    def update_service(self, zc: Zeroconf, service_type: str, name: str):
        """
        Called when a service is updated.

        Args:
            zc: Zeroconf instance
            service_type: Type of service
            name: Service name
        """
        logger.debug(f"mDNS service updated: {name}")

        try:
            info = zc.get_service_info(service_type, name)
            if info:
                self._process_service(info, service_type)
        except Exception as e:
            logger.error(f"Error updating mDNS service {name}: {e}")

    def remove_service(self, zc: Zeroconf, service_type: str, name: str):
        """
        Called when a service is removed.

        Args:
            zc: Zeroconf instance
            service_type: Type of service
            name: Service name
        """
        logger.debug(f"mDNS service removed: {name}")

        with self.lock:
            if name in self.discovered_services:
                del self.discovered_services[name]

    def _process_service(self, info: ServiceInfo, service_type: str):
        """
        Process discovered service and extract device information.

        Args:
            info: ServiceInfo object
            service_type: Service type string
        """
        try:
            # Extract device information
            device_info = self._extract_device_info(info, service_type)

            if not device_info:
                return

            # Store service
            with self.lock:
                self.discovered_services[info.name] = info

            # Notify callback
            if self.on_device_discovered:
                try:
                    self.on_device_discovered(device_info)
                except Exception as e:
                    logger.error(f"Error in discovery callback: {e}")

            logger.info(f"Discovered device via mDNS: {device_info.get('hostname')} at {device_info.get('ip_address')}")

        except Exception as e:
            logger.error(f"Error extracting device info: {e}")

    def _extract_device_info(self, info: ServiceInfo, service_type: str) -> Optional[Dict[str, Any]]:
        """
        Extract device information from ServiceInfo.

        Args:
            info: ServiceInfo object
            service_type: Service type

        Returns:
            Dictionary with device information or None
        """
        try:
            # Get IP addresses
            addresses = []
            if hasattr(info, 'addresses') and info.addresses:
                for addr in info.addresses:
                    try:
                        ip = socket.inet_ntoa(addr) if len(addr) == 4 else socket.inet_ntop(socket.AF_INET6, addr)
                        addresses.append(ip)
                    except Exception:
                        pass

            # Skip if no addresses
            if not addresses:
                return None

            # Parse service name for hostname
            hostname = info.name.split('.')[0] if info.name else 'unknown'

            # Extract properties from TXT records
            properties = {}
            if hasattr(info, 'properties') and info.properties:
                for key, value in info.properties.items():
                    try:
                        key_str = key.decode('utf-8') if isinstance(key, bytes) else str(key)
                        value_str = value.decode('utf-8') if isinstance(value, bytes) else str(value)
                        properties[key_str] = value_str
                    except Exception:
                        pass

            # Determine device type from service
            device_type = 'unknown'
            category = 'other'
            icon = '❓'
            manufacturer = ''

            if '_googlecast._tcp' in service_type:
                device_type = 'chromecast'
                category = 'entertainment'
                icon = '📱'
                manufacturer = 'Google'
            elif '_airplay._tcp' in service_type or '_raop._tcp' in service_type:
                device_type = 'airplay_device'
                category = 'entertainment'
                icon = '📱'
                manufacturer = 'Apple'
            elif '_hap._tcp' in service_type or '_homekit._tcp' in service_type:
                device_type = 'homekit_device'
                category = 'smart_home'
                icon = '🏠'
                manufacturer = 'Apple'
            elif '_philips-hue._tcp' in service_type:
                device_type = 'smart_bulb'
                category = 'smart_home'
                icon = '💡'
                manufacturer = 'Philips'
            elif '_spotify-connect._tcp' in service_type:
                device_type = 'smart_speaker'
                category = 'entertainment'
                icon = '🔊'
            elif '_printer._tcp' in service_type or '_ipp._tcp' in service_type:
                device_type = 'printer'
                category = 'office'
                icon = '🖨️'

            # Build device info dictionary
            device_info = {
                'ip_address': addresses[0],  # Primary IP
                'all_addresses': addresses,
                'hostname': hostname,
                'port': info.port,
                'service_type': service_type.replace('.local.', ''),
                'device_type': device_type,
                'manufacturer': manufacturer or properties.get('manufacturer', ''),
                'model': properties.get('model', properties.get('md', '')),
                'firmware_version': properties.get('fv', properties.get('firmware', '')),
                'category': category,
                'icon': icon,
                'properties': properties,
                'server': info.server if hasattr(info, 'server') else ''
            }

            return device_info

        except Exception as e:
            logger.error(f"Error extracting device info: {e}")
            return None

    def get_discovered_services(self) -> Dict[str, ServiceInfo]:
        """
        Get all discovered services.

        Returns:
            Dictionary of service name -> ServiceInfo
        """
        with self.lock:
            return dict(self.discovered_services)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get listener statistics.

        Returns:
            Dictionary with stats
        """
        with self.lock:
            total_services = len(self.discovered_services)

            # Count by service type
            by_type = {}
            for info in self.discovered_services.values():
                service_type = info.type if hasattr(info, 'type') else 'unknown'
                by_type[service_type] = by_type.get(service_type, 0) + 1

        return {
            'total_services': total_services,
            'by_service_type': by_type
        }


class MDNSDiscoveryManager:
    """
    Manages mDNS discovery with service browsing.

    Runs in background thread and monitors for IoT device advertisements.
    """

    def __init__(
        self,
        service_types: Optional[List[str]] = None,
        on_device_discovered: Optional[Callable] = None
    ):
        """
        Initialize mDNS discovery manager.

        Args:
            service_types: List of service types to monitor (None = default IoT services)
            on_device_discovered: Callback when device discovered
        """
        self.service_types = service_types or IOT_SERVICE_TYPES
        self.on_device_discovered = on_device_discovered

        self.zeroconf = None
        self.listener = None
        self.browsers = []
        self.running = False

        logger.info(f"mDNS discovery manager initialized with {len(self.service_types)} service types")

    def start(self):
        """Start mDNS discovery."""
        if self.running:
            logger.warning("mDNS discovery already running")
            return

        try:
            # Create Zeroconf instance
            self.zeroconf = Zeroconf()

            # Create listener
            self.listener = MDNSListener(on_device_discovered=self.on_device_discovered)

            # Create service browsers for each service type
            self.browsers = []
            for service_type in self.service_types:
                try:
                    browser = ServiceBrowser(self.zeroconf, service_type, self.listener)
                    self.browsers.append(browser)
                    logger.debug(f"Browsing for service: {service_type}")
                except Exception as e:
                    logger.warning(f"Could not browse service {service_type}: {e}")

            self.running = True
            logger.info(f"mDNS discovery started, monitoring {len(self.browsers)} service types")

        except Exception as e:
            logger.error(f"Error starting mDNS discovery: {e}")
            self.stop()

    def stop(self):
        """Stop mDNS discovery."""
        if not self.running:
            return

        logger.info("Stopping mDNS discovery...")
        self.running = False

        # Close browsers
        for browser in self.browsers:
            try:
                browser.cancel()
            except Exception as e:
                logger.warning(f"Error canceling browser: {e}")

        self.browsers.clear()

        # Close Zeroconf
        if self.zeroconf:
            try:
                self.zeroconf.close()
            except Exception as e:
                logger.warning(f"Error closing Zeroconf: {e}")
            self.zeroconf = None

        logger.info("mDNS discovery stopped")

    def get_discovered_devices(self) -> List[Dict[str, Any]]:
        """
        Get all discovered devices.

        Returns:
            List of device information dictionaries
        """
        if not self.listener:
            return []

        services = self.listener.get_discovered_services()
        devices = []

        for service_info in services.values():
            try:
                device_info = self.listener._extract_device_info(
                    service_info,
                    service_info.type if hasattr(service_info, 'type') else 'unknown'
                )
                if device_info:
                    devices.append(device_info)
            except Exception as e:
                logger.warning(f"Error extracting device info: {e}")

        return devices

    def get_stats(self) -> Dict[str, Any]:
        """Get discovery statistics."""
        if not self.listener:
            return {'running': False}

        stats = self.listener.get_stats()
        stats['running'] = self.running
        stats['monitored_service_types'] = len(self.service_types)
        stats['active_browsers'] = len(self.browsers)

        return stats


# Global discovery manager instance
_mdns_manager = None


def get_mdns_manager(
    on_device_discovered: Optional[Callable] = None
) -> MDNSDiscoveryManager:
    """
    Get global mDNS discovery manager instance.

    Args:
        on_device_discovered: Callback for device discovery

    Returns:
        MDNSDiscoveryManager instance
    """
    global _mdns_manager
    if _mdns_manager is None:
        _mdns_manager = MDNSDiscoveryManager(on_device_discovered=on_device_discovered)
    return _mdns_manager
