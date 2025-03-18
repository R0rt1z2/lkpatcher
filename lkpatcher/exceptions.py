"""
SPDX-FileCopyrightText: 2025 Roger Ortiz <me@r0rt1z2.com>
SPDX-License-Identifier: GPL-3.0-or-later
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union


class LkPatcherError(Exception):
    """Base exception for LK patcher-related errors."""

    def __init__(self, message: str):
        """
        Initialize the LK patcher error.

        Args:
            message: Descriptive error message
        """
        super().__init__(message)
        self.message = message


class InvalidIOFile(LkPatcherError):
    """
    Raised when a file cannot be read or written.

    Attributes:
        file: Path to the file that caused the error
        reason: Specific reason for I/O failure
    """

    def __init__(self, reason: str, file: Union[str, Path]):
        """
        Initialize the invalid I/O file error.

        Args:
            reason: Reason for I/O failure
            file: Path to the file that caused the error
        """
        super().__init__(f'Unable to access {file}: {reason}')
        self.file = file
        self.reason = reason


class NoNeedlesFound(LkPatcherError):
    """
    Raised when no patch needles are found in the image.

    Attributes:
        image: Path to the image where no needles were found
    """

    def __init__(self, image: Union[str, Path]):
        """
        Initialize the no needles found error.

        Args:
            image: Path to the image where no needles were found
        """
        super().__init__(f'No needles found in {image}')
        self.image = image


class ConfigurationError(LkPatcherError):
    """
    Raised when there's an error in the configuration.

    Attributes:
        config_file: Optional path to the configuration file
        detail: Detailed description of the configuration error
    """

    def __init__(
        self, detail: str, config_file: Optional[Union[str, Path]] = None
    ):
        """
        Initialize the configuration error.

        Args:
            detail: Detailed description of the configuration error
            config_file: Optional path to the configuration file
        """
        message = f'Configuration error: {detail}'
        if config_file:
            message = f'{message} (in {config_file})'
        super().__init__(message)
        self.detail = detail
        self.config_file = config_file


class PatchValidationError(LkPatcherError):
    """
    Raised when a patch fails validation.

    Attributes:
        needle: The invalid needle
        patch: The invalid patch
        reason: Reason for validation failure
    """

    def __init__(self, needle: str, patch: str, reason: str):
        """
        Initialize the patch validation error.

        Args:
            needle: The invalid needle
            patch: The invalid patch
            reason: Reason for validation failure
        """
        super().__init__(f'Invalid patch {needle} -> {patch}: {reason}')
        self.needle = needle
        self.patch = patch
        self.reason = reason
