"""
SPDX-FileCopyrightText: 2025 Roger Ortiz <me@r0rt1z2.com>
SPDX-License-Identifier: GPL-3.0-or-later
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List

from liblk.structures.partition import LkPartition


class SecurityPolicy:
    """
    Represents a security policy entry from the LK partition.

    Attributes:
        name: Policy name
        pol1: Policy for nosbc+lock state
        pol2: Policy for nosbc+unlock state
        pol3: Policy for sbc+lock state
        pol4: Policy for sbc+unlock state
    """

    def __init__(self, name: str, pol1: int, pol2: int, pol3: int, pol4: int):
        self.name = name
        self.pol1 = pol1
        self.pol2 = pol2
        self.pol3 = pol3
        self.pol4 = pol4

    def __str__(self) -> str:
        return (
            f'{self.name:<12}: {self.pol1} {self.pol2} {self.pol3} {self.pol4}'
        )


class SecurityPolicyAnalyzer:
    """
    Analyzes and modifies security policies within LK partitions.
    """

    POLICY_STRUCT_FORMAT = '<I IIII bbbb I'
    POLICY_STRUCT_SIZE = struct.calcsize(POLICY_STRUCT_FORMAT)
    LOCK_STATE_PATTERN = bytes.fromhex('7b44 1b68 db68 2360')
    LOCK_STATE_REPLACEMENT = bytes.fromhex('04 23')

    def __init__(self, lk_partition: LkPartition):
        """
        Initialize analyzer with an LK partition.

        Args:
            lk_partition: The LK partition to analyze
        """
        self.partition = lk_partition
        self.data = bytearray(lk_partition.data)
        self.load_address = self._get_load_address()
        self.address_mask = self._get_address_mask()

    def _get_load_address(self) -> int:
        """Get the load address from the partition header."""
        if (
            hasattr(self.partition, 'lk_address')
            and self.partition.lk_address is not None
        ):
            return self.partition.lk_address
        return self.partition.header.memory_address

    def _get_address_mask(self) -> int:
        """Determine address mask based on load address validity."""
        if self.load_address == 0xFFFFFFFF:
            return 0x000FFFFF
        return 0xFFFFFFFF

    def _find_default_policy_offsets(self) -> List[int]:
        """Find all candidate offsets for 'default' policy strings."""
        offsets = []
        search_pos = 0

        while True:
            pos = self.data.find(b'default\0', search_pos)
            if pos < 0:
                break
            offsets.append(pos)
            search_pos = pos + 1

        return offsets

    def _parse_policy_table(self, start_pos: int) -> List[SecurityPolicy]:
        """
        Parse security policy table starting at given position.

        Args:
            start_pos: Starting position in the data buffer

        Returns:
            List of SecurityPolicy objects
        """
        policies = []
        pos = start_pos

        while pos + self.POLICY_STRUCT_SIZE <= len(self.data):
            try:
                swid, p1, p2, p3, p4, pol1, pol2, pol3, pol4, hbind = (
                    struct.unpack(
                        self.POLICY_STRUCT_FORMAT,
                        self.data[pos : pos + self.POLICY_STRUCT_SIZE],
                    )
                )

                if p1 == 0:
                    break

                name_offset = (p1 - self.load_address) & self.address_mask
                if name_offset >= len(self.data):
                    break

                name_data = self.data[name_offset : name_offset + 128]
                name = name_data.split(b'\0')[0].decode('utf8')

                if name == 'NULL':
                    break

                policies.append(SecurityPolicy(name, pol1, pol2, pol3, pol4))
                pos += self.POLICY_STRUCT_SIZE

            except (struct.error, UnicodeDecodeError, IndexError):
                break

        return policies

    def analyze_security_policies(self) -> Dict[str, Any]:
        """
        Analyze security policies in the LK partition.

        Returns:
            Dictionary containing analysis results
        """
        default_offsets = self._find_default_policy_offsets()

        result = {
            'load_address': f'0x{self.load_address:08x}',
            'address_mask': f'0x{self.address_mask:08x}',
            'default_policy_candidates': len(default_offsets),
            'policies': [],
            'policy_table_found': False,
        }

        for i in range(0, len(self.data) - 4, 4):
            x = (
                int.from_bytes(self.data[i : i + 4], 'little')
                - self.load_address
            ) & self.address_mask

            if x in default_offsets:
                pos = i - 4
                if pos < 0 or pos + self.POLICY_STRUCT_SIZE > len(self.data):
                    continue

                try:
                    swid, p1, p2, p3, p4, pol1, pol2, pol3, pol4, hbind = (
                        struct.unpack(
                            self.POLICY_STRUCT_FORMAT,
                            self.data[pos : pos + self.POLICY_STRUCT_SIZE],
                        )
                    )

                    if swid != 0 or p2 != 0 or p3 != 0:
                        continue

                    if result['policy_table_found']:
                        result['warning'] = 'Multiple policy tables found'
                        continue

                    policies = self._parse_policy_table(pos)
                    if policies:
                        result['policies'] = [
                            {
                                'name': p.name,
                                'nosbc_lock': p.pol1,
                                'nosbc_unlock': p.pol2,
                                'sbc_lock': p.pol3,
                                'sbc_unlock': p.pol4,
                            }
                            for p in policies
                        ]
                        result['policy_table_found'] = True
                        result['policy_table_offset'] = f'0x{pos:x}'

                except struct.error:
                    continue

        return result

    def patch_security_policies(
        self, disable_verification: bool = True
    ) -> bool:
        """
        Patch security policies to disable verification.

        Args:
            disable_verification: Whether to set all policies to 0 (disabled)

        Returns:
            True if patches were applied successfully
        """
        patches_applied = 0
        default_offsets = self._find_default_policy_offsets()

        for i in range(0, len(self.data) - 4, 4):
            x = (
                int.from_bytes(self.data[i : i + 4], 'little')
                - self.load_address
            ) & self.address_mask

            if x in default_offsets:
                pos = i - 4
                if pos < 0:
                    continue

                try:
                    swid, p1, p2, p3, p4, pol1, pol2, pol3, pol4, hbind = (
                        struct.unpack(
                            self.POLICY_STRUCT_FORMAT,
                            self.data[pos : pos + self.POLICY_STRUCT_SIZE],
                        )
                    )

                    if swid != 0 or p2 != 0 or p3 != 0:
                        continue

                    table_pos = pos
                    while table_pos + self.POLICY_STRUCT_SIZE <= len(self.data):
                        swid, p1, p2, p3, p4, pol1, pol2, pol3, pol4, hbind = (
                            struct.unpack(
                                self.POLICY_STRUCT_FORMAT,
                                self.data[
                                    table_pos : table_pos
                                    + self.POLICY_STRUCT_SIZE
                                ],
                            )
                        )

                        if p1 == 0:
                            break

                        if disable_verification:
                            pol1 = pol2 = pol3 = pol4 = 0

                        self.data[
                            table_pos : table_pos + self.POLICY_STRUCT_SIZE
                        ] = struct.pack(
                            self.POLICY_STRUCT_FORMAT,
                            swid,
                            p1,
                            p2,
                            p3,
                            p4,
                            pol1,
                            pol2,
                            pol3,
                            pol4,
                            hbind,
                        )

                        table_pos += self.POLICY_STRUCT_SIZE
                        patches_applied += 1

                except struct.error:
                    continue

        lock_state_patched = self._patch_lock_state()

        if patches_applied > 0 or lock_state_patched:
            self.partition._data = bytes(self.data)
            self.partition.header.data_size = len(self.partition._data)
            return True

        return False

    def _patch_lock_state(self) -> bool:
        """
        Patch seccfg_get_lock_state() to always return LKS_LOCKED (4).

        Returns:
            True if patch was applied
        """
        idx = self.data.find(self.LOCK_STATE_PATTERN)

        if idx < 0 or self.data.find(self.LOCK_STATE_PATTERN, idx + 1) >= 0:
            return False

        patch_pos = idx + 4
        self.data[patch_pos : patch_pos + len(self.LOCK_STATE_REPLACEMENT)] = (
            self.LOCK_STATE_REPLACEMENT
        )

        return True


def analyze_lk_security_policies(lk_partition: LkPartition) -> Dict[str, Any]:
    """
    Analyze security policies in an LK partition.

    Args:
        lk_partition: The LK partition to analyze

    Returns:
        Dictionary containing analysis results
    """
    analyzer = SecurityPolicyAnalyzer(lk_partition)
    return analyzer.analyze_security_policies()


def patch_lk_security_policies(
    lk_partition: LkPartition, disable_verification: bool = True
) -> bool:
    """
    Patch security policies in an LK partition.

    Args:
        lk_partition: The LK partition to patch
        disable_verification: Whether to disable verification policies

    Returns:
        True if patches were applied successfully
    """
    analyzer = SecurityPolicyAnalyzer(lk_partition)
    return analyzer.patch_security_policies(disable_verification)
