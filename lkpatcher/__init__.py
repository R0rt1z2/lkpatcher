"""
SPDX-FileCopyrightText: 2025 Roger Ortiz <me@r0rt1z2.com>
SPDX-License-Identifier: GPL-3.0-or-later
"""

from pathlib import Path
from typing import Final

from lkpatcher.config import PatcherConfig
from lkpatcher.exceptions import (
    ConfigurationError,
    InvalidIOFile,
    LkPatcherError,
    NoNeedlesFound,
    PatchValidationError,
)
from lkpatcher.patcher import LkPatcher, PatchManager

__version__: Final[str] = '4.0.1'
__author__: Final[str] = 'Roger Ortiz <me@r0rt1z2.com>'
__description__: Final[str] = 'MediaTek bootloader patcher'

module_path: Final[Path] = Path(__file__).parent
current_path: Final[Path] = Path.cwd()

__all__ = [
    # Classes
    'LkPatcher',
    'PatchManager',
    'PatcherConfig',
    # Exceptions
    'LkPatcherError',
    'InvalidIOFile',
    'NoNeedlesFound',
    'ConfigurationError',
    'PatchValidationError',
    # Constants
    'module_path',
    'current_path',
    '__version__',
    '__author__',
    '__description__',
]
