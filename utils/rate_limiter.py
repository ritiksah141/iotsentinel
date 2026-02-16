"""
Rate Limiter for Login Attempts and Bulk Operations
Prevents brute force attacks and abuse by limiting attempts
Enhanced version with database persistence for distributed rate limiting
"""

import time
import logging
from collections import defaultdict
from typing import Tuple
from datetime import datetime, timedelta
from flask import request

logger = logging.getLogger(__name__)


class LoginRateLimiter:
    """Simple in-memory rate limiter for login attempts (legacy support)"""

    def __init__(self, max_attempts: int = 5, lockout_duration: int = 300):
        """
        Initialize rate limiter

        Args:
            max_attempts: Maximum failed attempts before lockout
            lockout_duration: Lockout duration in seconds (default: 5 minutes)
        """
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration

        # Track failed attempts: {identifier: [(timestamp1, timestamp2, ...)]}
        self._failed_attempts = defaultdict(list)

        # Track lockout times: {identifier: lockout_timestamp}
        self._lockouts = {}

    def is_locked_out(self, identifier: str) -> Tuple[bool, int]:
        """
        Check if an identifier (IP or username) is currently locked out

        Args:
            identifier: IP address or username to check

        Returns:
            Tuple of (is_locked, remaining_seconds)
        """
        if identifier in self._lockouts:
            lockout_time = self._lockouts[identifier]
            elapsed = time.time() - lockout_time

            if elapsed < self.lockout_duration:
                remaining = int(self.lockout_duration - elapsed)
                return True, remaining
            else:
                # Lockout expired, clean up
                del self._lockouts[identifier]
                self._failed_attempts[identifier] = []

        return False, 0

    def record_failed_attempt(self, identifier: str) -> Tuple[bool, int]:
        """
        Record a failed login attempt

        Args:
            identifier: IP address or username

        Returns:
            Tuple of (is_now_locked, remaining_attempts)
        """
        current_time = time.time()

        # Clean up old attempts (older than lockout duration)
        self._failed_attempts[identifier] = [
            t for t in self._failed_attempts[identifier]
            if current_time - t < self.lockout_duration
        ]

        # Add new failed attempt
        self._failed_attempts[identifier].append(current_time)

        # Check if we've exceeded max attempts
        attempt_count = len(self._failed_attempts[identifier])

        if attempt_count >= self.max_attempts:
            # Lock out the identifier
            self._lockouts[identifier] = current_time
            return True, 0

        remaining = self.max_attempts - attempt_count
        return False, remaining

    def record_successful_login(self, identifier: str):
        """
        Record a successful login and reset attempt counter

        Args:
            identifier: IP address or username
        """
        if identifier in self._failed_attempts:
            del self._failed_attempts[identifier]
        if identifier in self._lockouts:
            del self._lockouts[identifier]

    def get_attempt_count(self, identifier: str) -> int:
        """
        Get current number of failed attempts for an identifier

        Args:
            identifier: IP address or username

        Returns:
            Number of failed attempts
        """
        return len(self._failed_attempts.get(identifier, []))


# Enhanced Database-Backed Rate Limiter
class RateLimiter:
    """Database-backed rate limiting for login attempts and bulk operations."""

    # Rate limit configurations (attempts, window in minutes)
    LIMITS = {
        'login': (5, 15),           # 5 attempts per 15 minutes
        'bulk_operation': (3, 5),   # 3 bulk ops per 5 minutes
        'device_block': (10, 5),    # 10 device blocks per 5 minutes
        'api_call': (60, 1),        # 60 API calls per minute
    }

    def __init__(self, db_manager):
        """Initialize rate limiter with database connection."""
        self.db_manager = db_manager

    def check_rate_limit(self, identifier, action_type):
        """
        Check if action is within rate limit.

        Args:
            identifier: User identifier (username, IP, user_id)
            action_type: Type of action being limited

        Returns:
            tuple: (allowed: bool, remaining: int, reset_seconds: int)
        """
        if action_type not in self.LIMITS:
            return True, -1, 0

        max_attempts, window_minutes = self.LIMITS[action_type]

        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            # Get IP address for additional context
            ip_address = request.remote_addr if request else None

            # Count recent attempts within the time window
            window_start = datetime.now() - timedelta(minutes=window_minutes)

            cursor.execute('''
                SELECT COUNT(*) as count
                FROM rate_limit_log
                WHERE identifier = ?
                AND action_type = ?
                AND timestamp > ?
            ''', (identifier, action_type, window_start))

            result = cursor.fetchone()
            attempt_count = result['count'] if result else 0

            # Calculate remaining attempts
            remaining = max(0, max_attempts - attempt_count)

            # Find oldest attempt to calculate when window resets
            cursor.execute('''
                SELECT MIN(timestamp) as oldest
                FROM rate_limit_log
                WHERE identifier = ?
                AND action_type = ?
                AND timestamp > ?
            ''', (identifier, action_type, window_start))

            oldest_result = cursor.fetchone()
            if oldest_result and oldest_result['oldest']:
                oldest_time = datetime.fromisoformat(oldest_result['oldest'])
                reset_time = oldest_time + timedelta(minutes=window_minutes)
                reset_seconds = max(0, int((reset_time - datetime.now()).total_seconds()))
            else:
                reset_seconds = 0

            allowed = attempt_count < max_attempts

            return allowed, remaining, reset_seconds

        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            # Fail open - allow action if rate limiting fails
            return True, -1, 0

    def record_attempt(self, identifier, action_type, success=True):
        """Record an attempt for rate limiting."""
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()

            ip_address = request.remote_addr if request else None

            cursor.execute('''
                INSERT INTO rate_limit_log (identifier, action_type, ip_address, success)
                VALUES (?, ?, ?, ?)
            ''', (identifier, action_type, ip_address, 1 if success else 0))

            conn.commit()

        except Exception as e:
            logger.error(f"Failed to record rate limit attempt: {e}")

    def is_rate_limited(self, identifier, action_type):
        """Simple check if action is rate limited."""
        allowed, _, _ = self.check_rate_limit(identifier, action_type)
        return not allowed

    def cleanup_old_records(self, hours_to_keep=24):
        """Remove old rate limit records."""
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM rate_limit_log
                WHERE timestamp < datetime('now', '-' || ? || ' hours')
            ''', (hours_to_keep,))
            deleted_count = cursor.rowcount
            conn.commit()

            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old rate limit records")

            return deleted_count

        except Exception as e:
            logger.error(f"Failed to cleanup rate limit records: {e}")
            return 0


    def clear_all(self):
        """Clear all rate limiting data (for testing/debugging)."""
        try:
            conn = self.db_manager.conn
            cursor = conn.cursor()
            cursor.execute('DELETE FROM rate_limit_log')
            deleted = cursor.rowcount
            conn.commit()
            logger.info(f"Cleared {deleted} rate limit records")
            return deleted
        except Exception as e:
            logger.error(f"Failed to clear rate limit records: {e}")
            return 0
