/**
 * Browser Push Notifications for IoTSentinel Dashboard
 *
 * Handles Web Notifications API and real-time event streaming
 */

class NotificationManager {
    constructor() {
        this.permission = 'default';
        this.enabled = false;
        this.eventSource = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 5000; // 5 seconds
        this.notificationQueue = [];
        this.maxQueueSize = 50;

        // Load settings from localStorage
        this.loadSettings();

        // Initialize on page load
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.initialize());
        } else {
            this.initialize();
        }
    }

    /**
     * Initialize notification manager
     */
    async initialize() {
        console.log('Initializing Notification Manager...');

        // Check browser support
        if (!('Notification' in window)) {
            console.warn('This browser does not support desktop notifications');
            return;
        }

        // Get current permission
        this.permission = Notification.permission;
        console.log('Current notification permission:', this.permission);

        // If enabled in settings and permission granted, connect
        if (this.enabled && this.permission === 'granted') {
            this.connectEventStream();
        }
    }

    /**
     * Request notification permission from user
     */
    async requestPermission() {
        if (!('Notification' in window)) {
            alert('This browser does not support desktop notifications');
            return false;
        }

        try {
            const permission = await Notification.requestPermission();
            this.permission = permission;

            if (permission === 'granted') {
                console.log('Notification permission granted');
                this.enabled = true;
                this.saveSettings();

                // Show test notification
                this.showNotification({
                    title: '✅ Notifications Enabled',
                    body: 'You will now receive real-time security alerts',
                    type: 'system'
                });

                // Connect to event stream
                this.connectEventStream();
                return true;
            } else {
                console.log('Notification permission denied');
                return false;
            }
        } catch (error) {
            console.error('Error requesting notification permission:', error);
            return false;
        }
    }

    /**
     * Enable notifications
     */
    async enable() {
        if (this.permission === 'granted') {
            this.enabled = true;
            this.saveSettings();
            this.connectEventStream();
            return true;
        } else if (this.permission === 'default') {
            return await this.requestPermission();
        } else {
            alert('Notifications are blocked. Please enable them in your browser settings.');
            return false;
        }
    }

    /**
     * Disable notifications
     */
    disable() {
        this.enabled = false;
        this.saveSettings();
        this.disconnectEventStream();
        console.log('Notifications disabled');
    }

    /**
     * Connect to Server-Sent Events stream
     */
    connectEventStream() {
        if (this.eventSource && this.eventSource.readyState !== EventSource.CLOSED) {
            console.log('Event stream already connected');
            return;
        }

        try {
            // Generate unique client ID
            const clientId = this.getClientId();

            // Connect to SSE endpoint
            this.eventSource = new EventSource(`/notifications/stream?client_id=${clientId}`);

            this.eventSource.onopen = () => {
                console.log('Connected to notification stream');
                this.reconnectAttempts = 0;
            };

            this.eventSource.onmessage = (event) => {
                try {
                    const notification = JSON.parse(event.data);
                    this.handleNotification(notification);
                } catch (error) {
                    console.error('Error parsing notification:', error);
                }
            };

            this.eventSource.onerror = (error) => {
                console.error('Event stream error:', error);
                this.eventSource.close();
                this.reconnect();
            };

        } catch (error) {
            console.error('Error connecting to event stream:', error);
            this.reconnect();
        }
    }

    /**
     * Disconnect from event stream
     */
    disconnectEventStream() {
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
            console.log('Disconnected from notification stream');
        }
    }

    /**
     * Reconnect to event stream with exponential backoff
     */
    reconnect() {
        if (!this.enabled) {
            return;
        }

        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            return;
        }

        this.reconnectAttempts++;
        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

        console.log(`Reconnecting in ${delay / 1000} seconds... (attempt ${this.reconnectAttempts})`);

        setTimeout(() => {
            this.connectEventStream();
        }, delay);
    }

    /**
     * Handle incoming notification
     */
    handleNotification(notification) {
        console.log('Received notification:', notification);

        // Add to queue
        this.addToQueue(notification);

        // Show browser notification if enabled
        if (this.enabled && this.permission === 'granted') {
            this.showNotification(notification);
        }

        // Trigger custom event for dashboard to handle
        const event = new CustomEvent('iotsentinel-notification', {
            detail: notification
        });
        document.dispatchEvent(event);

        // Play sound based on severity
        this.playNotificationSound(notification);
    }

    /**
     * Show browser notification
     */
    showNotification(notification) {
        const title = notification.title || 'IoTSentinel Alert';
        const options = {
            body: notification.body || '',
            icon: '/assets/icon.png',
            badge: '/assets/badge.png',
            tag: notification.alert_id || notification.type || 'iotsentinel',
            requireInteraction: notification.severity === 'critical',
            silent: false,
            data: notification
        };

        // Add action buttons for alerts
        if (notification.type === 'alert' || notification.type === 'rule_triggered') {
            options.actions = [
                {
                    action: 'view',
                    title: 'View Details'
                },
                {
                    action: 'acknowledge',
                    title: 'Acknowledge'
                }
            ];
        }

        const browserNotification = new Notification(title, options);

        // Handle notification click
        browserNotification.onclick = (event) => {
            event.preventDefault();
            window.focus();

            // Navigate to alerts page if needed
            if (notification.type === 'alert' && notification.alert_id) {
                // Trigger navigation (implementation depends on your routing)
                console.log('Navigate to alert:', notification.alert_id);
            }

            browserNotification.close();
        };

        // Auto-close after 10 seconds (except critical)
        if (notification.severity !== 'critical') {
            setTimeout(() => {
                browserNotification.close();
            }, 10000);
        }
    }

    /**
     * Play notification sound based on severity
     */
    playNotificationSound(notification) {
        // Skip if sounds disabled in settings
        if (!this.getSetting('soundEnabled', true)) {
            return;
        }

        try {
            const soundMap = {
                'critical': 'critical-alert.mp3',
                'high': 'high-alert.mp3',
                'medium': 'medium-alert.mp3',
                'low': 'low-alert.mp3',
                'info': 'info-beep.mp3'
            };

            const severity = notification.severity || notification.notification_type || 'info';
            const soundFile = soundMap[severity.toLowerCase()] || 'info-beep.mp3';

            const audio = new Audio(`/assets/sounds/${soundFile}`);
            audio.volume = this.getSetting('soundVolume', 0.5);
            audio.play().catch(err => {
                // Ignore errors (e.g., if sound file doesn't exist)
                console.debug('Could not play notification sound:', err);
            });
        } catch (error) {
            console.debug('Error playing sound:', error);
        }
    }

    /**
     * Add notification to queue
     */
    addToQueue(notification) {
        this.notificationQueue.unshift(notification);

        // Limit queue size
        if (this.notificationQueue.length > this.maxQueueSize) {
            this.notificationQueue = this.notificationQueue.slice(0, this.maxQueueSize);
        }

        // Save to localStorage
        try {
            localStorage.setItem('iotsentinel_notification_queue', JSON.stringify(this.notificationQueue));
        } catch (error) {
            console.error('Error saving notification queue:', error);
        }
    }

    /**
     * Get notification queue
     */
    getQueue() {
        return this.notificationQueue;
    }

    /**
     * Clear notification queue
     */
    clearQueue() {
        this.notificationQueue = [];
        try {
            localStorage.removeItem('iotsentinel_notification_queue');
        } catch (error) {
            console.error('Error clearing notification queue:', error);
        }
    }

    /**
     * Get or create unique client ID
     */
    getClientId() {
        let clientId = localStorage.getItem('iotsentinel_client_id');
        if (!clientId) {
            clientId = 'client_' + Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
            localStorage.setItem('iotsentinel_client_id', clientId);
        }
        return clientId;
    }

    /**
     * Load settings from localStorage
     */
    loadSettings() {
        try {
            const settings = JSON.parse(localStorage.getItem('iotsentinel_notification_settings') || '{}');
            this.enabled = settings.enabled || false;

            // Load queue
            const queue = JSON.parse(localStorage.getItem('iotsentinel_notification_queue') || '[]');
            this.notificationQueue = queue;
        } catch (error) {
            console.error('Error loading notification settings:', error);
        }
    }

    /**
     * Save settings to localStorage
     */
    saveSettings() {
        try {
            const settings = {
                enabled: this.enabled,
                permission: this.permission
            };
            localStorage.setItem('iotsentinel_notification_settings', JSON.stringify(settings));
        } catch (error) {
            console.error('Error saving notification settings:', error);
        }
    }

    /**
     * Get setting value
     */
    getSetting(key, defaultValue = null) {
        try {
            const settings = JSON.parse(localStorage.getItem('iotsentinel_notification_settings') || '{}');
            return settings[key] !== undefined ? settings[key] : defaultValue;
        } catch (error) {
            return defaultValue;
        }
    }

    /**
     * Set setting value
     */
    setSetting(key, value) {
        try {
            const settings = JSON.parse(localStorage.getItem('iotsentinel_notification_settings') || '{}');
            settings[key] = value;
            localStorage.setItem('iotsentinel_notification_settings', JSON.stringify(settings));
        } catch (error) {
            console.error('Error setting notification setting:', error);
        }
    }

    /**
     * Get current status
     */
    getStatus() {
        return {
            supported: 'Notification' in window,
            permission: this.permission,
            enabled: this.enabled,
            connected: this.eventSource && this.eventSource.readyState === EventSource.OPEN,
            queueSize: this.notificationQueue.length
        };
    }
}

// Create global instance
window.iotsentinelNotifications = new NotificationManager();

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = NotificationManager;
}
