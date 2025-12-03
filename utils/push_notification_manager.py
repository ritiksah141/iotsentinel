#!/usr/bin/env python3
"""
Browser Push Notification Manager for IoTSentinel

Manages browser push notifications using Server-Sent Events (SSE)
and Web Notifications API for real-time alerts.
"""

import json
import logging
import queue
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class PushNotificationManager:
    """Manages browser push notifications and real-time events"""

    def __init__(self):
        """Initialize push notification manager"""
        self.subscribers: Dict[str, queue.Queue] = {}
        self.lock = threading.Lock()
        logger.info("Push notification manager initialized")

    def subscribe(self, client_id: str) -> queue.Queue:
        """
        Subscribe a client to push notifications.

        Args:
            client_id: Unique client identifier

        Returns:
            Queue for receiving notifications
        """
        with self.lock:
            if client_id not in self.subscribers:
                self.subscribers[client_id] = queue.Queue(maxsize=100)
                logger.info(f"Client {client_id} subscribed to push notifications")

            return self.subscribers[client_id]

    def unsubscribe(self, client_id: str):
        """
        Unsubscribe a client from push notifications.

        Args:
            client_id: Client identifier to unsubscribe
        """
        with self.lock:
            if client_id in self.subscribers:
                del self.subscribers[client_id]
                logger.info(f"Client {client_id} unsubscribed from push notifications")

    def get_subscriber_count(self) -> int:
        """Get number of active subscribers"""
        with self.lock:
            return len(self.subscribers)

    def broadcast(self, notification: Dict[str, Any]):
        """
        Broadcast notification to all subscribers.

        Args:
            notification: Notification data to broadcast
        """
        with self.lock:
            dead_clients = []

            for client_id, client_queue in self.subscribers.items():
                try:
                    # Non-blocking put - if queue is full, skip this client
                    client_queue.put_nowait(notification)
                except queue.Full:
                    logger.warning(f"Queue full for client {client_id}, notification dropped")
                    dead_clients.append(client_id)
                except Exception as e:
                    logger.error(f"Error broadcasting to client {client_id}: {e}")
                    dead_clients.append(client_id)

            # Clean up dead clients
            for client_id in dead_clients:
                del self.subscribers[client_id]

            logger.debug(f"Broadcasted notification to {len(self.subscribers)} clients")

    def send_to_client(self, client_id: str, notification: Dict[str, Any]):
        """
        Send notification to specific client.

        Args:
            client_id: Target client identifier
            notification: Notification data to send
        """
        with self.lock:
            if client_id in self.subscribers:
                try:
                    self.subscribers[client_id].put_nowait(notification)
                    logger.debug(f"Sent notification to client {client_id}")
                except queue.Full:
                    logger.warning(f"Queue full for client {client_id}")
                except Exception as e:
                    logger.error(f"Error sending to client {client_id}: {e}")

    def create_alert_notification(
        self,
        device_ip: str,
        device_name: str,
        severity: str,
        explanation: str,
        alert_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Create an alert notification.

        Args:
            device_ip: Device IP address
            device_name: Device name
            severity: Alert severity
            explanation: Alert explanation
            alert_id: Alert database ID

        Returns:
            Notification dictionary
        """
        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵'
        }

        return {
            'type': 'alert',
            'timestamp': datetime.now().isoformat(),
            'alert_id': alert_id,
            'device_ip': device_ip,
            'device_name': device_name or 'Unknown Device',
            'severity': severity,
            'severity_icon': severity_icons.get(severity.lower(), '⚪'),
            'explanation': explanation,
            'title': f'{severity_icons.get(severity.lower(), "⚠️")} Security Alert: {severity.upper()}',
            'body': f'{device_name or device_ip}: {explanation}'
        }

    def create_device_notification(
        self,
        device_ip: str,
        device_name: str,
        event_type: str,
        message: str
    ) -> Dict[str, Any]:
        """
        Create a device event notification.

        Args:
            device_ip: Device IP address
            device_name: Device name
            event_type: Event type (new_device, device_blocked, etc.)
            message: Event message

        Returns:
            Notification dictionary
        """
        event_icons = {
            'new_device': '📱',
            'device_blocked': '🚫',
            'device_unblocked': '✅',
            'device_offline': '⚠️',
            'device_online': '✅'
        }

        return {
            'type': 'device_event',
            'timestamp': datetime.now().isoformat(),
            'device_ip': device_ip,
            'device_name': device_name or 'Unknown Device',
            'event_type': event_type,
            'icon': event_icons.get(event_type, '📢'),
            'title': f'{event_icons.get(event_type, "📢")} Device Event',
            'body': message
        }

    def create_system_notification(
        self,
        message: str,
        notification_type: str = 'info'
    ) -> Dict[str, Any]:
        """
        Create a system notification.

        Args:
            message: Notification message
            notification_type: Type (info, warning, error, success)

        Returns:
            Notification dictionary
        """
        type_icons = {
            'info': 'ℹ️',
            'warning': '⚠️',
            'error': '❌',
            'success': '✅'
        }

        return {
            'type': 'system',
            'timestamp': datetime.now().isoformat(),
            'notification_type': notification_type,
            'icon': type_icons.get(notification_type, 'ℹ️'),
            'title': f'{type_icons.get(notification_type, "ℹ️")} System Notification',
            'body': message
        }

    def create_rule_triggered_notification(
        self,
        rule_name: str,
        device_ip: str,
        device_name: str,
        severity: str,
        explanation: str
    ) -> Dict[str, Any]:
        """
        Create a custom rule triggered notification.

        Args:
            rule_name: Rule name that was triggered
            device_ip: Device IP address
            device_name: Device name
            severity: Alert severity
            explanation: Explanation of why rule triggered

        Returns:
            Notification dictionary
        """
        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🔵'
        }

        return {
            'type': 'rule_triggered',
            'timestamp': datetime.now().isoformat(),
            'rule_name': rule_name,
            'device_ip': device_ip,
            'device_name': device_name or 'Unknown Device',
            'severity': severity,
            'severity_icon': severity_icons.get(severity.lower(), '⚪'),
            'explanation': explanation,
            'title': f'{severity_icons.get(severity.lower(), "⚠️")} Alert Rule: {rule_name}',
            'body': f'{device_name or device_ip}: {explanation}'
        }


# Global instance
push_manager = PushNotificationManager()


def notify_new_alert(
    device_ip: str,
    device_name: str,
    severity: str,
    explanation: str,
    alert_id: Optional[int] = None
):
    """
    Send push notification for new alert.

    Args:
        device_ip: Device IP address
        device_name: Device name
        severity: Alert severity
        explanation: Alert explanation
        alert_id: Alert database ID
    """
    notification = push_manager.create_alert_notification(
        device_ip=device_ip,
        device_name=device_name,
        severity=severity,
        explanation=explanation,
        alert_id=alert_id
    )
    push_manager.broadcast(notification)
    logger.info(f"Broadcasted alert notification for {device_ip}")


def notify_device_event(
    device_ip: str,
    device_name: str,
    event_type: str,
    message: str
):
    """
    Send push notification for device event.

    Args:
        device_ip: Device IP address
        device_name: Device name
        event_type: Event type
        message: Event message
    """
    notification = push_manager.create_device_notification(
        device_ip=device_ip,
        device_name=device_name,
        event_type=event_type,
        message=message
    )
    push_manager.broadcast(notification)
    logger.info(f"Broadcasted device event for {device_ip}: {event_type}")


def notify_rule_triggered(
    rule_name: str,
    device_ip: str,
    device_name: str,
    severity: str,
    explanation: str
):
    """
    Send push notification for custom rule trigger.

    Args:
        rule_name: Rule name
        device_ip: Device IP address
        device_name: Device name
        severity: Alert severity
        explanation: Explanation
    """
    notification = push_manager.create_rule_triggered_notification(
        rule_name=rule_name,
        device_ip=device_ip,
        device_name=device_name,
        severity=severity,
        explanation=explanation
    )
    push_manager.broadcast(notification)
    logger.info(f"Broadcasted rule trigger notification: {rule_name}")


def notify_system(message: str, notification_type: str = 'info'):
    """
    Send system notification.

    Args:
        message: Notification message
        notification_type: Type (info, warning, error, success)
    """
    notification = push_manager.create_system_notification(
        message=message,
        notification_type=notification_type
    )
    push_manager.broadcast(notification)
    logger.info(f"Broadcasted system notification: {message}")
