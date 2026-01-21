#!/usr/bin/env python3
"""
Enhanced Logging Setup for IoTSentinel Dashboard

Integrates production-ready features:
- Log rotation
- Environment-based configuration
- Optional structured logging
- Performance optimizations
"""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Dict, List

try:
    from utils.production_logging import (
        ProductionLoggingConfig,
        JSONFormatter,
        ComplianceLogger
    )
    PRODUCTION_LOGGING_AVAILABLE = True
except ImportError:
    PRODUCTION_LOGGING_AVAILABLE = False


def setup_production_logging(log_dir: str = 'data/logs') -> Dict[str, logging.Logger]:
    """
    Setup production-ready logging with all industry-standard features.

    Features:
    - Automatic log rotation (50MB max, 10 backups)
    - Environment-based log levels
    - Optional structured JSON logging
    - Credential sanitization
    - Performance optimized

    Args:
        log_dir: Directory for log files

    Returns:
        Dictionary of configured loggers
    """
    # Create log directory
    os.makedirs(log_dir, exist_ok=True)

    # Get production config if available
    if PRODUCTION_LOGGING_AVAILABLE:
        log_level = ProductionLoggingConfig.get_log_level()
        use_console = ProductionLoggingConfig.should_use_console()
        formatter = ProductionLoggingConfig.get_formatter()
        is_production = ProductionLoggingConfig.IS_PRODUCTION
    else:
        # Fallback to defaults
        log_level = logging.INFO
        use_console = True
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        is_production = False

    # Audit formatter (simpler for audit logs)
    audit_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Configure loggers
    loggers = {}

    # Log configurations: (name, filename, level, use_audit_formatter)
    log_configs = [
        ('main', 'iotsentinel.log', log_level, False),
        ('audit', 'audit.log', logging.INFO, True),
        ('ml', 'ml.log', log_level, False),
        ('alerts', 'alerts.log', logging.INFO, False),
        ('hardware', 'hardware.log', log_level, False),
        ('database', 'database.log', log_level, False),
        ('errors', 'error.log', logging.ERROR, False),
        ('api', 'api.log', logging.INFO, False),
    ]

    # Setup each logger
    for logger_name, filename, level, use_audit_fmt in log_configs:
        log_path = os.path.join(log_dir, filename)

        # Create rotating file handler (production best practice)
        if PRODUCTION_LOGGING_AVAILABLE and is_production:
            file_handler = ProductionLoggingConfig.create_rotating_handler(log_path)
        else:
            # Use rotating handler even in dev for disk space safety
            file_handler = logging.handlers.RotatingFileHandler(
                log_path,
                maxBytes=50 * 1024 * 1024,  # 50MB
                backupCount=10,
                encoding='utf-8'
            )

        # Set formatter
        file_handler.setFormatter(audit_formatter if use_audit_fmt else formatter)

        # Get or create logger
        if logger_name == 'main':
            logger = logging.getLogger()
            logger.setLevel(level)
            logger.handlers.clear()  # Clear any existing handlers
        else:
            logger = logging.getLogger(logger_name)
            logger.setLevel(level)
            logger.propagate = False  # Don't propagate to root

        logger.addHandler(file_handler)

        # Add console handler if enabled
        if use_console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(level)
            logger.addHandler(console_handler)

        loggers[logger_name] = logger

    # Configure root logger to send ERROR+ to error.log
    error_handler = loggers['errors'].handlers[0]
    logging.getLogger().addHandler(error_handler)

    # Log startup message
    main_logger = loggers.get('main', logging.getLogger())
    main_logger.info("=" * 70)
    main_logger.info("IoTSentinel Logging System Initialized")
    main_logger.info(f"Environment: {ProductionLoggingConfig.ENV if PRODUCTION_LOGGING_AVAILABLE else 'development'}")
    main_logger.info(f"Log Level: {logging.getLevelName(log_level)}")
    main_logger.info(f"Log Directory: {os.path.abspath(log_dir)}")
    main_logger.info(f"Log Rotation: {'Enabled (50MB, 10 backups)' if is_production else 'Enabled'}")
    main_logger.info(f"Console Output: {'Enabled' if use_console else 'Disabled'}")
    main_logger.info(f"Structured Logging: {'Enabled' if PRODUCTION_LOGGING_AVAILABLE and ProductionLoggingConfig.STRUCTURED_LOGGING else 'Disabled'}")
    main_logger.info("Active Logs: iotsentinel.log, audit.log, ml.log, alerts.log,")
    main_logger.info("             hardware.log, database.log, error.log, api.log")
    main_logger.info("=" * 70)

    return loggers


def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger instance with proper configuration.

    Args:
        name: Logger name (use __name__ in your module)

    Returns:
        Configured logger
    """
    return logging.getLogger(name)


# Convenience functions for common logging tasks
def log_security_event(username: str, action: str, success: bool = True, details: str = None):
    """Log a security-related event to audit log."""
    audit_logger = logging.getLogger('audit')
    level = logging.INFO if success else logging.WARNING

    message = f"User: {username} | Action: {action} | Success: {success}"
    if details:
        message += f" | Details: {details}"

    audit_logger.log(level, message)


def log_api_call(service: str, endpoint: str, status_code: int = None, response_time_ms: int = None):
    """Log an external API call."""
    api_logger = logging.getLogger('api')

    message = f"API Call: {service} | Endpoint: {endpoint}"
    if status_code:
        message += f" | Status: {status_code}"
    if response_time_ms:
        message += f" | Time: {response_time_ms}ms"

    api_logger.info(message)


def log_ml_operation(operation: str, details: Dict = None):
    """Log a machine learning operation."""
    ml_logger = logging.getLogger('ml')

    message = f"ML Operation: {operation}"
    if details:
        message += f" | {details}"

    ml_logger.info(message)


def log_hardware_event(event: str, gpio_pin: int = None, state: str = None):
    """Log a hardware event (Raspberry Pi GPIO)."""
    hardware_logger = logging.getLogger('hardware')

    message = f"🔧 HARDWARE: {event}"
    if gpio_pin:
        message += f" | GPIO{gpio_pin}"
    if state:
        message += f" | State: {state}"

    hardware_logger.info(message)


# Export commonly used functions
__all__ = [
    'setup_production_logging',
    'get_logger',
    'log_security_event',
    'log_api_call',
    'log_ml_operation',
    'log_hardware_event',
]
