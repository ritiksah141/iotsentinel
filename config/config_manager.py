#!/usr/bin/env python3
"""
Professional Configuration Manager for IoTSentinel

Loads configuration with priority:
1. Environment variables (highest)
2. User config (~/.iotsentinel/config.json)
3. Project config (config/config.json)
4. Default config (config/default_config.json)
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import copy

logger = logging.getLogger(__name__)


class ConfigManager:
    """Singleton configuration manager."""
    
    PROJECT_ROOT = Path(__file__).parent.parent
    DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default_config.json"
    PROJECT_CONFIG_PATH = PROJECT_ROOT / "config" / "config.json"
    USER_CONFIG_PATH = Path.home() / ".iotsentinel" / "config.json"
    
    _instance = None
    _config = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._config is None:
            self.reload()
    
    def reload(self):
        """Load configuration from all sources."""
        # Start with default
        self._config = self._load_json(self.DEFAULT_CONFIG_PATH)
        
        # Merge project config
        if self.PROJECT_CONFIG_PATH.exists():
            project_config = self._load_json(self.PROJECT_CONFIG_PATH)
            self._deep_merge(self._config, project_config)
        
        # Merge user config
        if self.USER_CONFIG_PATH.exists():
            user_config = self._load_json(self.USER_CONFIG_PATH)
            self._deep_merge(self._config, user_config)
        
        # Apply environment overrides
        self._apply_env_overrides()
        
        # Resolve paths
        self._resolve_paths()
    
    def _load_json(self, path: Path) -> Dict:
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load config from {path}: {e}")
            return {}
    
    def _deep_merge(self, base: Dict, override: Dict):
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _apply_env_overrides(self):
        env_mappings = {
            'IOTSENTINEL_INTERFACE': ['network', 'interface'],
            'IOTSENTINEL_DB_PATH': ['database', 'path'],
            'IOTSENTINEL_DASHBOARD_PORT': ['dashboard', 'port'],
            'IOTSENTINEL_LOG_LEVEL': ['logging', 'level'],
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                current = self._config
                for key in config_path[:-1]:
                    current = current.setdefault(key, {})
                
                final_key = config_path[-1]
                if isinstance(current.get(final_key), int):
                    current[final_key] = int(value)
                elif isinstance(current.get(final_key), bool):
                    current[final_key] = value.lower() in ('true', '1', 'yes')
                else:
                    current[final_key] = value
    
    def _resolve_paths(self):
        """Convert relative paths to absolute."""
        # Database
        db_path = Path(self._config['database']['path'])
        if not db_path.is_absolute():
            self._config['database']['path'] = str(self.PROJECT_ROOT / db_path)
        
        # Logs
        log_dir = Path(self._config['logging']['log_dir'])
        if not log_dir.is_absolute():
            self._config['logging']['log_dir'] = str(self.PROJECT_ROOT / log_dir)
        
        # Models
        for key in ['autoencoder_path', 'isolation_forest_path', 'feature_extractor_path']:
            if key in self._config['ml']:
                model_path = Path(self._config['ml'][key])
                if not model_path.is_absolute():
                    self._config['ml'][key] = str(self.PROJECT_ROOT / model_path)
    
    def get(self, *keys, default=None) -> Any:
        """Get config value by path."""
        current = self._config
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current
    
    def set(self, *keys, value):
        """Set config value by path."""
        current = self._config
        for key in keys[:-1]:
            current = current.setdefault(key, {})
        current[keys[-1]] = value
    
    def get_all(self) -> Dict:
        return copy.deepcopy(self._config)
    
    def save(self, path: Optional[Path] = None):
        if path is None:
            path = self.PROJECT_CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self._config, f, indent=4)
    
    def is_pi(self) -> bool:
        try:
            with open('/proc/cpuinfo', 'r') as f:
                return 'Raspberry Pi' in f.read()
        except:
            return False
    
    def get_platform(self) -> str:
        if self.is_pi():
            return 'raspberry_pi'
        elif os.uname().sysname == 'Darwin':
            return 'macos'
        elif os.uname().sysname == 'Linux':
            return 'linux'
        else:
            return 'windows'


# Global instance
config = ConfigManager()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    print(f"Platform: {config.get_platform()}")
    print(f"Interface: {config.get('network', 'interface')}")
    print(f"Database: {config.get('database', 'path')}")