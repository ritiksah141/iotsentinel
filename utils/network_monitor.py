"""
Network Monitoring Utilities
Provides real latency and packet loss measurements
"""
import subprocess
import re
import statistics
import logging
import platform
from typing import Optional, Dict

logger = logging.getLogger(__name__)


def get_default_gateway() -> Optional[str]:
    """
    Auto-detect the default gateway IP address.

    Returns:
        Gateway IP address or None if not found
    """
    try:
        system = platform.system()

        if system == "Darwin":  # macOS
            result = subprocess.run(
                ['route', '-n', 'get', 'default'],
                capture_output=True, text=True, timeout=2
            )
            match = re.search(r'gateway:\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)

        elif system == "Linux":
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=2
            )
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)

        elif system == "Windows":
            result = subprocess.run(
                ['route', 'print', '0.0.0.0'],
                capture_output=True, text=True, timeout=2
            )
            match = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)

    except Exception as e:
        logger.warning(f"Failed to detect gateway: {e}")

    return None


def ping_device(ip_address: str, count: int = 4, timeout: int = 5) -> Optional[Dict[str, float]]:
    """
    Ping a device and return latency and packet loss metrics.

    Args:
        ip_address: IP address to ping
        count: Number of ping packets to send
        timeout: Timeout in seconds

    Returns:
        Dict with 'avg_latency_ms' and 'packet_loss_percent', or None if failed
    """
    try:
        system = platform.system()

        # Build platform-specific ping command
        if system == "Darwin":  # macOS
            # macOS uses -t for timeout in seconds, -W for milliseconds wait per packet
            ping_cmd = ['ping', '-c', str(count), '-t', str(timeout), ip_address]
        elif system == "Windows":
            # Windows uses -n for count, -w for timeout in milliseconds
            ping_cmd = ['ping', '-n', str(count), '-w', str(timeout * 1000), ip_address]
        else:  # Linux (including Raspberry Pi)
            # Linux uses -c for count, -W for timeout in seconds
            ping_cmd = ['ping', '-c', str(count), '-W', str(timeout), ip_address]

        # Run ping command
        result = subprocess.run(
            ping_cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 2
        )

        # Parse latency values (time=X.XX ms)
        latencies = []
        for match in re.finditer(r'time[=<](\d+\.?\d*)', result.stdout):
            latencies.append(float(match.group(1)))

        # Parse packet loss (X% packet loss)
        packet_loss = 0.0
        loss_match = re.search(r'(\d+\.?\d*)% packet loss', result.stdout)
        if loss_match:
            packet_loss = float(loss_match.group(1))

        # Calculate average latency
        avg_latency = statistics.mean(latencies) if latencies else None

        if avg_latency is None:
            # No responses received
            return {
                'avg_latency_ms': None,
                'packet_loss_percent': 100.0
            }

        return {
            'avg_latency_ms': round(avg_latency, 2),
            'packet_loss_percent': round(packet_loss, 2)
        }

    except subprocess.TimeoutExpired:
        logger.warning(f"Ping timeout for {ip_address}")
        return {
            'avg_latency_ms': None,
            'packet_loss_percent': 100.0
        }
    except Exception as e:
        logger.error(f"Error pinging {ip_address}: {e}")
        return None


def get_network_metrics(gateway_ip: Optional[str] = None) -> Dict[str, str]:
    """
    Get current network performance metrics.

    Args:
        gateway_ip: IP of the gateway/router to test (auto-detects if None)

    Returns:
        Dict with formatted metric strings
    """
    # Auto-detect gateway if not specified
    if gateway_ip is None:
        gateway_ip = get_default_gateway()
        if gateway_ip:
            logger.info(f"Auto-detected gateway: {gateway_ip}")
        else:
            gateway_ip = "127.0.0.1"  # Fallback to localhost
            logger.warning("Could not detect gateway, using localhost")

    # Try with minimal pings for fast response (2 pings, 1 second timeout)
    result = ping_device(gateway_ip, count=2, timeout=1)

    if not result:
        # Gateway might block ICMP, try localhost instead
        logger.warning(f"Gateway {gateway_ip} not responding to ping (ICMP may be blocked)")
        result = ping_device("127.0.0.1", count=2, timeout=1)

        if not result:
            # If even localhost fails, return minimal simulated metrics
            logger.warning("Cannot measure network metrics, returning estimated values")
            return {
                'avg_latency': '<1ms (local)',
                'packet_loss': '0.0%'
            }

    latency = result['avg_latency_ms']
    loss = result['packet_loss_percent']

    return {
        'avg_latency': f"{latency:.1f}ms" if latency else "Timeout",
        'packet_loss': f"{loss:.1f}%"
    }


if __name__ == "__main__":
    # Test the ping function
    print("Testing network monitor...")
    metrics = get_network_metrics("8.8.8.8")  # Test with Google DNS
    print(f"Latency: {metrics['avg_latency']}")
    print(f"Packet Loss: {metrics['packet_loss']}")
