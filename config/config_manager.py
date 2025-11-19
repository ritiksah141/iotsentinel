"""
Configuration Manager for IoTSentinel

Loads configuration from a default JSON file and overrides with environment
variables from a .env file for secure credential management.
"""

import json
import os
from pathlib import Path
from dotenv import load_dotenv

class ConfigManager:
    """Manages loading and accessing configuration."""

    def __init__(self, default_config_path: Path, env_path: Path = None):
        # Load default config
        with open(default_config_path, 'r') as f:
            self._config = json.load(f)

        # Load environment variables from .env file
        if env_path and env_path.exists():
            load_dotenv(dotenv_path=env_path)

        # Override with environment variables
        self._override_with_env()

    def _override_with_env(self):
        """Override JSON config with environment variables."""
        for section, settings in self._config.items():
            for key, _ in settings.items():
                env_var_name = f"{section.upper()}_{key.upper()}"
                env_var_value = os.getenv(env_var_name)
                if env_var_value is not None:
                    self._config[section][key] = env_var_value

    def get(self, section: str, key: str, default: any = None) -> any:
        """
        Get a configuration value.

        Args:
            section: The configuration section (e.g., 'database').
            key: The configuration key (e.g., 'path').
            default: The default value to return if not found.

        Returns:
            The configuration value.
        """
        return self._config.get(section, {}).get(key, default)

    def get_section(self, section: str) -> dict:
        """Get a whole configuration section."""
        return self._config.get(section, {})

# Initialize a single config instance for the application
project_root = Path(__file__).parent.parent
default_config_path = project_root / 'config' / 'default_config.json'
env_path = project_root / '.env'

config = ConfigManager(default_config_path, env_path)
