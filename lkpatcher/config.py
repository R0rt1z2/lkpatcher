"""
SPDX-FileCopyrightText: 2025 Roger Ortiz <me@r0rt1z2.com>
SPDX-License-Identifier: GPL-3.0-or-later
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, Optional, Set, Union

from lkpatcher.exceptions import ConfigurationError


class LogLevel(Enum):
    """Log levels for the patcher."""

    DEBUG = auto()
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()

    @classmethod
    def from_string(cls, value: str) -> LogLevel:
        """
        Convert string representation to LogLevel enum.

        Args:
            value: String representation of log level

        Returns:
            Corresponding LogLevel enum value

        Raises:
            ValueError: If string doesn't match any log level
        """
        value = value.upper()
        try:
            return cls[value]
        except KeyError:
            valid_levels = [level.name for level in cls]
            raise ValueError(
                f'Invalid log level: {value}. Valid levels: {", ".join(valid_levels)}'
            )

    def to_logging_level(self) -> int:
        """
        Convert to Python's logging module level.

        Returns:
            Corresponding logging module level as integer
        """
        return {
            LogLevel.DEBUG: logging.DEBUG,
            LogLevel.INFO: logging.INFO,
            LogLevel.WARNING: logging.WARNING,
            LogLevel.ERROR: logging.ERROR,
            LogLevel.CRITICAL: logging.CRITICAL,
        }[self]


@dataclass
class PatcherConfig:
    """
    Configuration for the LK patcher.

    Attributes:
        log_level: Logging level for the patcher
        backup: Whether to create backups before patching
        backup_dir: Directory for storing backups
        verify_patch: Whether to verify patches before applying
        allow_incomplete: Whether to continue if not all patches apply
        dry_run: Whether to perform a dry run without writing changes
        patch_categories: Categories of patches to apply (empty for all)
        exclude_categories: Categories of patches to exclude
    """

    log_level: LogLevel = LogLevel.INFO
    backup: bool = False
    backup_dir: Optional[Path] = None
    verify_patch: bool = True
    allow_incomplete: bool = True
    dry_run: bool = False
    patch_categories: Set[str] = field(default_factory=set)
    exclude_categories: Set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PatcherConfig:
        """
        Create configuration from dictionary.

        Args:
            data: Dictionary containing configuration values

        Returns:
            PatcherConfig instance

        Raises:
            ConfigurationError: If configuration is invalid
        """
        config = cls()

        try:
            if 'log_level' in data:
                config.log_level = LogLevel.from_string(data['log_level'])

            for bool_field in [
                'backup',
                'verify_patch',
                'allow_incomplete',
                'dry_run',
            ]:
                if bool_field in data:
                    setattr(config, bool_field, bool(data[bool_field]))

            if 'backup_dir' in data:
                backup_dir = Path(data['backup_dir'])
                if not backup_dir.exists():
                    backup_dir.mkdir(parents=True, exist_ok=True)
                config.backup_dir = backup_dir

            if 'patch_categories' in data:
                config.patch_categories = set(data['patch_categories'])

            if 'exclude_categories' in data:
                config.exclude_categories = set(data['exclude_categories'])

        except (ValueError, TypeError, OSError) as e:
            raise ConfigurationError(str(e))

        return config

    @classmethod
    def from_file(cls, file_path: Union[str, Path]) -> PatcherConfig:
        """
        Load configuration from a JSON file.

        Args:
            file_path: Path to the JSON configuration file

        Returns:
            PatcherConfig instance

        Raises:
            ConfigurationError: If file cannot be read or parsed
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            return cls.from_dict(data)
        except FileNotFoundError:
            raise ConfigurationError('Configuration file not found', file_path)
        except json.JSONDecodeError as e:
            raise ConfigurationError(f'Invalid JSON: {e}', file_path)
        except Exception as e:
            raise ConfigurationError(str(e), file_path)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.

        Returns:
            Dictionary representation of configuration
        """
        return {
            'log_level': self.log_level.name,
            'backup': self.backup,
            'backup_dir': str(self.backup_dir) if self.backup_dir else None,
            'verify_patch': self.verify_patch,
            'allow_incomplete': self.allow_incomplete,
            'dry_run': self.dry_run,
            'patch_categories': list(self.patch_categories),
            'exclude_categories': list(self.exclude_categories),
        }

    def save(self, file_path: Union[str, Path]) -> None:
        """
        Save configuration to a JSON file.

        Args:
            file_path: Path where configuration will be saved

        Raises:
            ConfigurationError: If file cannot be written
        """
        try:
            with open(file_path, 'w') as f:
                json.dump(self.to_dict(), f, indent=4)
        except (OSError, IOError) as e:
            raise ConfigurationError(
                f'Failed to save configuration: {e}', file_path
            )

    def should_apply_category(self, category: str) -> bool:
        """
        Determine if a patch category should be applied.

        Args:
            category: Patch category name

        Returns:
            True if category should be applied, False otherwise
        """
        if category in self.exclude_categories:
            return False

        if not self.patch_categories:
            return True

        return category in self.patch_categories
