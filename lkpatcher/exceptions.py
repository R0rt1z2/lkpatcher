#
# This file is part of 'lkpatcher'. Copyright (c) 2023 Roger Ortiz.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from pathlib import Path
from typing import Union

class InvalidIOFile(Exception):
    """Raised when we fail to read/write a file"""
    def __init__(self, message: str, file: Union[str, Path]) -> None:
        self.file = file
        self.message = message

    def __str__(self) -> str:
        return f"Unable to open {self.file}: {self.message}"

class NoNeedlesFound(Exception):
    """Raised when we fail to find any needles"""