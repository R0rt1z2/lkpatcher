"""
SPDX-FileCopyrightText: 2025 Roger Ortiz <me@r0rt1z2.com>
SPDX-License-Identifier: GPL-3.0-or-later
"""

from pathlib import Path
from typing import Final

from lkpatcher.cert_bypass import CertBypassMode
from lkpatcher.config import PatcherConfig
from lkpatcher.exceptions import (
    ConfigurationError,
    InvalidIOFile,
    LkPatcherError,
    NoNeedlesFound,
    PatchValidationError,
)
from lkpatcher.patcher import LkPatcher, PatchManager

__version__: Final[str] = '4.2.0'
__author__: Final[str] = 'Roger Ortiz <me@r0rt1z2.com>'
__description__: Final[str] = 'MediaTek bootloader patcher'

module_path: Final[Path] = Path(__file__).parent
current_path: Final[Path] = Path.cwd()

__all__ = [
    'CertBypassMode',
    'ConfigurationError',
    'InvalidIOFile',
    'LkPatcher',
    'LkPatcherError',
    'NoNeedlesFound',
    'PatchManager',
    'PatchValidationError',
    'PatcherConfig',
    '__author__',
    '__description__',
    '__version__',
    'current_path',
    'module_path',
]
