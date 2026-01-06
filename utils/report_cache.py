#!/usr/bin/env python3
"""
Report Caching Module for IoTSentinel

Provides intelligent caching for frequently generated reports to improve
performance and reduce database load.
"""

import os
import json
import logging
import hashlib
import time
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from threading import Lock

logger = logging.getLogger(__name__)


class ReportCache:
    """
    Manages caching of generated reports.

    Features:
    - In-memory and disk-based caching
    - Configurable TTL (time-to-live)
    - Automatic cache invalidation
    - Cache size limits
    - Thread-safe operations
    """

    def __init__(
        self,
        cache_dir: str = 'data/cache/reports',
        max_cache_size_mb: int = 100,
        default_ttl_minutes: int = 15,
        enable_disk_cache: bool = True,
        enable_memory_cache: bool = True
    ):
        """
        Initialize report cache.

        Args:
            cache_dir: Directory for disk-based cache
            max_cache_size_mb: Maximum cache size in MB
            default_ttl_minutes: Default time-to-live for cache entries
            enable_disk_cache: Enable disk-based caching
            enable_memory_cache: Enable in-memory caching
        """
        self.cache_dir = Path(cache_dir)
        self.max_cache_size = max_cache_size_mb * 1024 * 1024  # Convert to bytes
        self.default_ttl = timedelta(minutes=default_ttl_minutes)
        self.enable_disk_cache = enable_disk_cache
        self.enable_memory_cache = enable_memory_cache

        # In-memory cache: {cache_key: (report_data, expiry_time, size)}
        self._memory_cache: Dict[str, Tuple[Any, datetime, int]] = {}
        self._cache_lock = Lock()

        # Create cache directory
        if self.enable_disk_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Report cache initialized at {self.cache_dir}")

    def _generate_cache_key(
        self,
        template_name: str,
        format_type: str,
        parameters: Dict[str, Any]
    ) -> str:
        """
        Generate unique cache key for report configuration.

        Args:
            template_name: Report template name
            format_type: Output format (pdf, excel, json)
            parameters: Report parameters

        Returns:
            MD5 hash of the configuration
        """
        # Create deterministic string from parameters
        param_str = json.dumps(parameters, sort_keys=True)
        config_str = f"{template_name}:{format_type}:{param_str}"

        # Generate hash
        cache_key = hashlib.md5(config_str.encode()).hexdigest()
        return cache_key

    def _get_cache_metadata_path(self, cache_key: str) -> Path:
        """Get path to cache metadata file."""
        return self.cache_dir / f"{cache_key}.meta"

    def _get_cache_data_path(self, cache_key: str) -> Path:
        """Get path to cached report data file."""
        return self.cache_dir / f"{cache_key}.data"

    def get(
        self,
        template_name: str,
        format_type: str,
        parameters: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached report if available and not expired.

        Args:
            template_name: Report template name
            format_type: Output format
            parameters: Report parameters

        Returns:
            Cached report data or None if not found/expired
        """
        cache_key = self._generate_cache_key(template_name, format_type, parameters)

        with self._cache_lock:
            # Check memory cache first
            if self.enable_memory_cache and cache_key in self._memory_cache:
                report_data, expiry_time, _ = self._memory_cache[cache_key]

                if datetime.now() < expiry_time:
                    logger.info(f"Report cache HIT (memory): {cache_key[:8]}")
                    return report_data
                else:
                    # Expired, remove from cache
                    logger.info(f"Report cache EXPIRED (memory): {cache_key[:8]}")
                    del self._memory_cache[cache_key]

            # Check disk cache
            if self.enable_disk_cache:
                meta_path = self._get_cache_metadata_path(cache_key)
                data_path = self._get_cache_data_path(cache_key)

                if meta_path.exists() and data_path.exists():
                    try:
                        # Read metadata
                        with open(meta_path, 'r') as f:
                            metadata = json.load(f)

                        expiry_time = datetime.fromisoformat(metadata['expiry_time'])

                        if datetime.now() < expiry_time:
                            # Read cached data
                            with open(data_path, 'rb' if format_type in ['pdf', 'excel'] else 'r') as f:
                                content = f.read()

                            report_data = {
                                'content': content,
                                'filename': metadata['filename'],
                                'format': format_type,
                                'generated_at': metadata['generated_at'],
                                'cached': True
                            }

                            logger.info(f"Report cache HIT (disk): {cache_key[:8]}")

                            # Load into memory cache for faster subsequent access
                            if self.enable_memory_cache:
                                size = len(content) if isinstance(content, (bytes, str)) else 0
                                self._memory_cache[cache_key] = (report_data, expiry_time, size)

                            return report_data
                        else:
                            # Expired, remove files
                            logger.info(f"Report cache EXPIRED (disk): {cache_key[:8]}")
                            meta_path.unlink(missing_ok=True)
                            data_path.unlink(missing_ok=True)

                    except Exception as e:
                        logger.error(f"Error reading cache: {e}")
                        # Clean up corrupted cache files
                        meta_path.unlink(missing_ok=True)
                        data_path.unlink(missing_ok=True)

        logger.info(f"Report cache MISS: {cache_key[:8]}")
        return None

    def put(
        self,
        template_name: str,
        format_type: str,
        parameters: Dict[str, Any],
        report_data: Dict[str, Any],
        ttl_minutes: Optional[int] = None
    ) -> bool:
        """
        Store report in cache.

        Args:
            template_name: Report template name
            format_type: Output format
            parameters: Report parameters
            report_data: Generated report data
            ttl_minutes: Custom TTL in minutes (uses default if None)

        Returns:
            True if successfully cached
        """
        cache_key = self._generate_cache_key(template_name, format_type, parameters)
        ttl = timedelta(minutes=ttl_minutes) if ttl_minutes else self.default_ttl
        expiry_time = datetime.now() + ttl

        content = report_data.get('content')
        if not content:
            logger.warning("Cannot cache report without content")
            return False

        size = len(content) if isinstance(content, (bytes, str)) else 0

        with self._cache_lock:
            # Check if we need to clean cache due to size limits
            self._enforce_size_limit(size)

            # Store in memory cache
            if self.enable_memory_cache:
                self._memory_cache[cache_key] = (report_data, expiry_time, size)
                logger.info(f"Report cached in memory: {cache_key[:8]} (TTL: {ttl_minutes or self.default_ttl.seconds//60}min)")

            # Store in disk cache
            if self.enable_disk_cache:
                try:
                    meta_path = self._get_cache_metadata_path(cache_key)
                    data_path = self._get_cache_data_path(cache_key)

                    # Write metadata
                    metadata = {
                        'template_name': template_name,
                        'format': format_type,
                        'parameters': parameters,
                        'filename': report_data.get('filename', 'report'),
                        'generated_at': report_data.get('generated_at', datetime.now().isoformat()),
                        'expiry_time': expiry_time.isoformat(),
                        'size_bytes': size
                    }

                    with open(meta_path, 'w') as f:
                        json.dump(metadata, f, indent=2)

                    # Write report data
                    mode = 'wb' if format_type in ['pdf', 'excel'] else 'w'
                    with open(data_path, mode) as f:
                        f.write(content)

                    logger.info(f"Report cached on disk: {cache_key[:8]} ({size / 1024:.1f} KB)")

                except Exception as e:
                    logger.error(f"Error writing cache to disk: {e}")
                    return False

        return True

    def _enforce_size_limit(self, incoming_size: int):
        """
        Enforce cache size limits by removing oldest entries.

        Args:
            incoming_size: Size of new entry to be added
        """
        if not self.enable_memory_cache:
            return

        # Calculate current cache size
        current_size = sum(size for _, _, size in self._memory_cache.values())

        # If adding new entry would exceed limit, remove oldest entries
        if current_size + incoming_size > self.max_cache_size:
            # Sort by expiry time (oldest first)
            sorted_cache = sorted(
                self._memory_cache.items(),
                key=lambda x: x[1][1]  # Sort by expiry_time
            )

            # Remove oldest entries until we have space
            removed_count = 0
            for cache_key, (_, _, size) in sorted_cache:
                if current_size + incoming_size <= self.max_cache_size:
                    break

                del self._memory_cache[cache_key]
                current_size -= size
                removed_count += 1

            if removed_count > 0:
                logger.info(f"Evicted {removed_count} cache entries to enforce size limit")

    def invalidate(
        self,
        template_name: Optional[str] = None,
        format_type: Optional[str] = None
    ):
        """
        Invalidate cache entries matching criteria.

        Args:
            template_name: Invalidate specific template (None = all)
            format_type: Invalidate specific format (None = all)
        """
        with self._cache_lock:
            # Invalidate memory cache
            if self.enable_memory_cache:
                keys_to_remove = []
                for key in self._memory_cache:
                    # For now, remove all if no specific criteria
                    # In future, could parse key to match template/format
                    if template_name is None and format_type is None:
                        keys_to_remove.append(key)

                for key in keys_to_remove:
                    del self._memory_cache[key]

                logger.info(f"Invalidated {len(keys_to_remove)} memory cache entries")

            # Invalidate disk cache
            if self.enable_disk_cache:
                removed_count = 0
                for meta_file in self.cache_dir.glob("*.meta"):
                    try:
                        with open(meta_file, 'r') as f:
                            metadata = json.load(f)

                        should_remove = True
                        if template_name and metadata.get('template_name') != template_name:
                            should_remove = False
                        if format_type and metadata.get('format') != format_type:
                            should_remove = False

                        if should_remove:
                            cache_key = meta_file.stem
                            data_file = self._get_cache_data_path(cache_key)

                            meta_file.unlink(missing_ok=True)
                            data_file.unlink(missing_ok=True)
                            removed_count += 1

                    except Exception as e:
                        logger.error(f"Error invalidating cache file: {e}")

                logger.info(f"Invalidated {removed_count} disk cache entries")

    def clear_expired(self):
        """Remove all expired cache entries."""
        with self._cache_lock:
            now = datetime.now()

            # Clear expired memory cache
            if self.enable_memory_cache:
                expired_keys = [
                    key for key, (_, expiry, _) in self._memory_cache.items()
                    if now >= expiry
                ]

                for key in expired_keys:
                    del self._memory_cache[key]

                if expired_keys:
                    logger.info(f"Cleared {len(expired_keys)} expired memory cache entries")

            # Clear expired disk cache
            if self.enable_disk_cache:
                removed_count = 0
                for meta_file in self.cache_dir.glob("*.meta"):
                    try:
                        with open(meta_file, 'r') as f:
                            metadata = json.load(f)

                        expiry = datetime.fromisoformat(metadata['expiry_time'])
                        if now >= expiry:
                            cache_key = meta_file.stem
                            data_file = self._get_cache_data_path(cache_key)

                            meta_file.unlink(missing_ok=True)
                            data_file.unlink(missing_ok=True)
                            removed_count += 1

                    except Exception as e:
                        logger.error(f"Error clearing expired cache: {e}")

                if removed_count > 0:
                    logger.info(f"Cleared {removed_count} expired disk cache entries")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        with self._cache_lock:
            memory_entries = len(self._memory_cache)
            memory_size = sum(size for _, _, size in self._memory_cache.values())

            disk_entries = len(list(self.cache_dir.glob("*.meta"))) if self.enable_disk_cache else 0

            return {
                'memory_cache': {
                    'enabled': self.enable_memory_cache,
                    'entries': memory_entries,
                    'size_mb': round(memory_size / (1024 * 1024), 2),
                    'max_size_mb': round(self.max_cache_size / (1024 * 1024), 2)
                },
                'disk_cache': {
                    'enabled': self.enable_disk_cache,
                    'entries': disk_entries,
                    'location': str(self.cache_dir)
                },
                'default_ttl_minutes': int(self.default_ttl.total_seconds() / 60)
            }
