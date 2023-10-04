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