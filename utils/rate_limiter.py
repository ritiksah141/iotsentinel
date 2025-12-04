"""
Rate Limiter for Login Attempts
Prevents brute force attacks by limiting login attempts per IP/username
"""

import time
from collections import defaultdict
from typing import Tuple


class LoginRateLimiter:
    """Simple rate limiter for login attempts"""

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

    def clear_all(self):
        """Clear all rate limiting data (for testing/debugging)"""
        self._failed_attempts.clear()
        self._lockouts.clear()
