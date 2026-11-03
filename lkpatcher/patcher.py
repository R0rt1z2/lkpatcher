"""
SPDX-FileCopyrightText: 2025 Roger Ortiz <me@r0rt1z2.com>
SPDX-License-Identifier: GPL-3.0-or-later
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, cast

from liblk.exceptions import NeedleNotFoundException
from liblk.image import LkImage
from liblk.structures.partition import LkPartition

from lkpatcher.config import PatcherConfig
from lkpatcher.exceptions import (
    ConfigurationError,
    InvalidIOFile,
    NoNeedlesFound,
    PatchValidationError,
)
from lkpatcher.policy import patch_lk_security_policies

if TYPE_CHECKING:
    from lkpatcher.cert_bypass import CertBypassMode


class PatchManager:
    """
    Manages patches for LK bootloader images.

    Handles loading patches from built-in defaults or custom JSON files,
    validates patch formats, and provides utilities to work with patch collections.

    Attributes:
        patches: Dictionary of patches organized by category
        patches_count: Total number of individual patches loaded
    """

    DEFAULT_PATCHES: ClassVar[dict[str, dict[str, str]]] = {
        # Unlock fastboot access by forcing the function
        # that checks for the unlock bit in oplusreserve
        # to always return 0 (unlocked)
        'fastboot': {
            '2de9f04fadf5ac5d': '00207047',
            'f0b5adf5925d': '00207047',
        },
        # Disable warning message that shows up when the device
        # gets unlocked with mtkclient by forcing the function
        # that checks for vbmeta state to always return 0
        'dm_verity': {
            '30b583b002ab0022': '00207047',
        },
        # Disable warning message that shows up when the device
        # gets unlocked by forcing the function that checks for
        # the current LCS state to always return 0
        'orange_state': {
            '08b50a4b7b441b681b68022b': '00207047',
            '08b50e4b7b441b681b68022b': '00207047',
        },
        # Force the function that prints the warning about
        # device verification to return immediately
        'red_state': {
            'f0b5002489b0': '00207047',
        },
    }

    def __init__(
        self,
        patches_file: Path | None = None,
        config: PatcherConfig | None = None,
    ) -> None:
        """
        Initialize the patch manager.

        Args:
            patches_file: Optional path to a JSON file with custom patches
            config: Optional configuration object
        """
        self.logger = logging.getLogger(__name__)
        self.patches: dict[str, dict[str, str]] = self.DEFAULT_PATCHES.copy()
        self.config = config or PatcherConfig()

        if patches_file:
            self.load_patches(patches_file)

        if self.config.verify_patch:
            self._validate_patches()

        self.patches_count = len(self.get_all_patches())
        self.logger.info(
            'Successfully loaded %d patches in %d categories',
            self.patches_count,
            len(self.patches),
        )

    def load_patches(self, file_path: Path) -> None:
        """
        Load patches from a JSON file.

        The file can either completely replace the default patches or
        add/update specific categories.

        Args:
            file_path: Path to the JSON file with patches

        Raises:
            InvalidIOFile: If the file cannot be read or parsed
            ConfigurationError: If the patch file has an invalid format
        """
        try:
            with open(file_path, 'r') as fp:
                patch_data = json.load(fp)

            if not isinstance(patch_data, dict):
                raise ConfigurationError(
                    'Patch file must contain a JSON object', file_path
                )

            mode = patch_data.pop('mode', 'update').lower()

            if mode == 'replace':
                self.patches = {}

            for category, patches in patch_data.items():
                if category == 'mode':
                    continue

                if not isinstance(patches, dict):
                    self.logger.warning(
                        "Skipping invalid category '%s': patches must be a dictionary",
                        category,
                    )
                    continue

                if category not in self.patches:
                    self.patches[category] = {}

                if mode == 'update':
                    self.patches[category].update(patches)
                else:
                    self.patches[category] = patches

        except FileNotFoundError:
            self.logger.warning('Patch file not found: %s', file_path)
        except json.JSONDecodeError as e:
            raise InvalidIOFile(f'Invalid JSON: {e}', file_path)

    def _validate_patches(self) -> None:
        """
        Validate all patch formats.

        Ensures that all needles and patches are valid hexadecimal strings.

        Raises:
            PatchValidationError: If a patch fails validation
        """
        hex_pattern = re.compile(r'^[0-9a-fA-F]+$')

        for category, patches in self.patches.items():
            for needle, patch in patches.items():
                if not hex_pattern.match(needle):
                    raise PatchValidationError(
                        needle,
                        patch,
                        f"Needle in category '{category}' is not a valid hex string",
                    )

                if not hex_pattern.match(patch):
                    raise PatchValidationError(
                        needle,
                        patch,
                        f"Patch in category '{category}' is not a valid hex string",
                    )

    def get_all_patches(self) -> list[str]:
        """
        Get a flat list of all patch needles.

        Returns:
            List of all unique patch needles
        """
        return [
            needle for category in self.patches.values() for needle in category
        ]

    def get_applicable_patches(self) -> dict[str, dict[str, str]]:
        """
        Get patches that should be applied based on configuration.

        Filters patches according to include/exclude categories in config.

        Returns:
            Dictionary of patches to apply
        """
        result: dict[str, dict[str, str]] = {}

        for category, patches in self.patches.items():
            if self.config.should_apply_category(category):
                result[category] = patches.copy()

        return result

    def export_patches(self, file_path: Path) -> None:
        """
        Export current patches to a JSON file.

        Args:
            file_path: Path where patches will be saved

        Raises:
            InvalidIOFile: If file cannot be written
        """
        try:
            with open(file_path, 'w') as fp:
                json.dump(self.patches, fp, indent=4)
        except OSError as e:
            raise InvalidIOFile(str(e), file_path)


class LkPatcher:
    """
    Patches MediaTek bootloader (LK) images.

    Applies binary patches to modify bootloader behavior, allowing
    for features like unlocking fastboot, disabling verification
    warnings, etc.

    Attributes:
        image: LkImage instance representing the bootloader
        patch_manager: Manager for available patches
        config: Configuration settings for the patcher
    """

    def __init__(
        self,
        image: str | Path,
        patches: Path | None = None,
        config: PatcherConfig | None = None,
        load_image: bool = True,
    ) -> None:
        """
        Initialize the LK patcher.

        Args:
            image: Path to the bootloader image
            patches: Optional path to JSON file with custom patches
            config: Optional configuration settings
            load_image: Whether to load the image immediately
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or PatcherConfig()
        self.patch_manager = PatchManager(patches, self.config)

        if load_image:
            self.image = LkImage(image)
            self.logger.info(
                'Loaded image from %s with %d partitions (version %d)',
                image,
                len(self.image.partitions),
                self.image.version,
            )
        else:
            self.image = cast(LkImage, None)

    def _rebuild_image_contents(self) -> None:
        """
        Rebuild the main image contents from modified partitions.
        This ensures that partition-level changes are reflected in the main image.
        """
        new_contents = bytearray()
        partition_names = list(self.image.partitions.keys())

        for i, (name, partition) in enumerate(self.image.partitions.items()):
            partition.header.image_list_end = (
                1 if i == len(partition_names) - 1 else 0
            )
            partition.end_offset = (
                len(new_contents)
                + partition.header.size
                + partition.header.data_size
            )

            alignment = (
                partition.header.alignment
                if partition.header.is_extended
                else 8
            )
            if alignment and partition.end_offset % alignment:
                partition.end_offset += alignment - (
                    partition.end_offset % alignment
                )

            new_contents.extend(bytes(partition))

        self.image.contents = new_contents

    def apply_cert_bypass(
        self, mode: CertBypassMode | None = None
    ) -> list[str]:
        """
        Re-sign modified partitions using the cert bypass.

        Args:
            mode: Strategy to use (see
                :class:`lkpatcher.cert_bypass.CertBypassMode`). Defaults to the
                override strategy.

        Returns:
            Names of the partitions that were re-signed
        """
        from lkpatcher.cert_bypass import CertBypassMode, apply_cert_bypass

        if mode is None:
            mode = CertBypassMode.OVERRIDE

        contents = bytes(self.image.contents)
        signed_image = LkImage(contents)

        region_end = 0
        for partition in signed_image.partitions.values():
            region_end = max(region_end, partition.end_offset)
            for cert in partition.certs:
                region_end = max(region_end, cert.end_offset)
        trailing = contents[region_end:]

        signed = apply_cert_bypass(signed_image, mode=mode)
        if signed:
            self.image.contents = bytearray(signed_image.contents) + bytearray(
                trailing
            )

            self.image.partitions = signed_image.partitions
        return signed

    def patch(
        self,
        output: str | Path,
        patch_policies: bool = False,
    ) -> Path:
        """
        Patch the bootloader image.

        Attempts to apply all available patches to the bootloader
        and saves the modified image to the specified output path.

        Args:
            output: Path where the patched image will be saved
            patch_policies: Whether to patch security policies

        Returns:
            Path to the saved patched image

        Raises:
            NoNeedlesFound: If no patches could be applied
            InvalidIOFile: If the output file cannot be written
        """
        applicable_patches = self.patch_manager.get_applicable_patches()

        if not applicable_patches and not patch_policies:
            self.logger.warning(
                'No applicable patches based on current configuration'
            )
            if self.config.dry_run:
                return Path(output)
            else:
                raise NoNeedlesFound(self.image.path or 'Unknown')

        self.logger.info(
            'Starting patching process with %d categories',
            len(applicable_patches),
        )

        total_patches = sum(
            len(patches) for patches in applicable_patches.values()
        )
        applied_count = 0
        skipped_count = 0

        results: dict[str, dict[str, bool]] = {}

        if self.image.contents:
            original_digest = sha256(self.image.contents).hexdigest()
            self.logger.debug('Original image SHA-256: %s', original_digest)

        for category, patches in list(applicable_patches.items()):
            category_results: dict[str, bool] = {}
            results[category] = category_results

            self.logger.info(
                'Processing category: %s (%d patches)', category, len(patches)
            )

            for needle, patch in list(patches.items()):
                if self.config.dry_run:
                    self.logger.info(
                        'DRY RUN: Would apply patch %s -> %s',
                        needle[:10] + '...' if len(needle) > 10 else needle,
                        patch[:10] + '...' if len(patch) > 10 else patch,
                    )
                    category_results[needle] = True
                    applied_count += 1
                    continue

                try:
                    self.image.apply_patch(needle, patch)
                    category_results[needle] = True
                    applied_count += 1
                    self.logger.debug(
                        'Successfully applied patch %s -> %s',
                        needle[:10] + '...' if len(needle) > 10 else needle,
                        patch[:10] + '...' if len(patch) > 10 else patch,
                    )
                except NeedleNotFoundException:
                    category_results[needle] = False
                    skipped_count += 1
                    self.logger.debug('Needle not found: %s', needle)

        if patch_policies:
            lk_partition = self.image.partitions.get('lk')
            if lk_partition:
                if self.config.dry_run:
                    self.logger.info('DRY RUN: Would patch security policies')
                    results['security_policies'] = {'policy_patch': True}
                    applied_count += 1
                else:
                    try:
                        policy_patched = patch_lk_security_policies(
                            lk_partition
                        )
                        if policy_patched:
                            self.logger.info(
                                'Successfully patched security policies'
                            )
                            self._rebuild_image_contents()
                            results['security_policies'] = {
                                'policy_patch': True
                            }
                            applied_count += 1
                        else:
                            self.logger.warning(
                                'No security policies were patched'
                            )
                            results['security_policies'] = {
                                'policy_patch': False
                            }
                            skipped_count += 1
                    except Exception as e:  # noqa: BLE001 - non-fatal step
                        self.logger.error(
                            'Failed to patch security policies: %s', e
                        )
                        results['security_policies'] = {'policy_patch': False}
                        skipped_count += 1
            else:
                self.logger.warning(
                    'LK partition not found for policy patching'
                )

        self.logger.info(
            'Patching summary: %d/%d patches applied, %d skipped',
            applied_count,
            total_patches + (1 if patch_policies else 0),
            skipped_count,
        )

        if applied_count == 0 and not self.config.dry_run:
            debug_path = f'{self.image.path}.debug.txt'
            with open(debug_path, 'w') as fp:
                fp.writelines(
                    f'{partition_name}:\n{partition}\n\n'
                    for partition_name, partition in self.image.partitions.items()
                )

            self.logger.info(
                'Dumped partition info to %s for debugging', debug_path
            )

            if not self.config.allow_incomplete:
                raise NoNeedlesFound(self.image.path or 'Unknown')
            else:
                self.logger.warning(
                    'No patches were applied, but continuing due to allow_incomplete=True'
                )

        if self.image.contents and not self.config.dry_run:
            new_digest = sha256(self.image.contents).hexdigest()
            self.logger.debug('New image SHA-256: %s', new_digest)

            if new_digest == original_digest and applied_count > 0:
                self.logger.warning(
                    'Warning: Image digest unchanged despite applying patches'
                )

        if not self.config.dry_run:
            try:
                self.image.save(output)
                self.logger.info('Saved patched image to %s', output)
            except (FileNotFoundError, PermissionError) as e:
                raise InvalidIOFile(str(e), output)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = Path(output).with_suffix('.patch_report.json')
        try:
            with open(report_path, 'w') as fp:
                report = {
                    'timestamp': timestamp,
                    'image': str(self.image.path),
                    'image_version': self.image.version,
                    'total_patches': total_patches
                    + (1 if patch_policies else 0),
                    'applied_patches': applied_count,
                    'skipped_patches': skipped_count,
                    'dry_run': self.config.dry_run,
                    'security_policies_patched': patch_policies,
                    'results': results,
                }
                json.dump(report, fp, indent=4)
                self.logger.debug('Patch report saved to %s', report_path)
        except OSError:
            self.logger.warning(
                'Failed to write patch report to %s', report_path
            )

        return Path(output)

    def replace_partition(
        self,
        name: str,
        data: bytes | bytearray | Path | str,
        memory_address: int | None = None,
    ) -> LkPartition:
        """
        Replace an existing partition's data in the LK image.

        Args:
            name: Name of the partition to replace
            data: New partition data or path to file containing data
            memory_address: Optional memory address for the partition

        Returns:
            The modified LkPartition

        Raises:
            KeyError: If partition not found
            InvalidIOFile: If data is a path and file cannot be read
        """
        if name not in self.image.partitions:
            raise KeyError(f"Partition '{name}' not found")

        if isinstance(data, (Path, str)):
            path = Path(data)
            if not path.exists():
                raise InvalidIOFile(f'Data file not found: {path}', path)
            try:
                with open(path, 'rb') as f:
                    partition_data = f.read()
            except OSError as e:
                raise InvalidIOFile(str(e), path)
        else:
            partition_data = bytes(data)

        partition = self.image.partitions[name]
        partition.data = partition_data

        if memory_address is not None:
            partition.header.memory_address = memory_address
            if name == 'lk':
                partition.lk_address = memory_address

        self.image._rebuild_contents()
        return partition

    def dump_partition(self, partition_name: str) -> Path | None:
        """
        Dump a specific partition from the bootloader image.

        Args:
            partition_name: Name of the partition to dump

        Returns:
            Path to the dumped partition file, or None if partition not found

        Raises:
            InvalidIOFile: If the partition file cannot be written
        """
        partition = self.image.partitions.get(partition_name)

        if not partition:
            self.logger.error('Partition not found: %s', partition_name)
            self.logger.info(
                'Available partitions: %s', list(self.image.partitions.keys())
            )
            return None

        print('=' * 40)
        print(str(partition))
        print('=' * 40)

        if self.image.path:
            base_name = Path(self.image.path).stem
            output_path = f'{base_name}_{partition_name}.bin'
        else:
            output_path = f'{partition_name}.bin'

        try:
            partition.save(output_path)
            self.logger.info(
                'Successfully dumped partition %s to %s',
                partition_name,
                output_path,
            )
            return Path(output_path)
        except (FileNotFoundError, PermissionError) as e:
            raise InvalidIOFile(str(e), output_path)

    def extract_all_partitions(self, output_dir: str | Path) -> list[Path]:
        """
        Extract all partitions from the bootloader image.

        Args:
            output_dir: Directory where partitions will be saved

        Returns:
            List of paths to saved partition files

        Raises:
            InvalidIOFile: If files cannot be written
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        saved_paths: list[Path] = []
        for partition_name, partition in self.image.partitions.items():
            safe_name = ''.join(
                c if c.isalnum() else '_' for c in partition_name
            )
            output_path = output_dir / f'{safe_name}.bin'

            try:
                partition.save(output_path)
                self.logger.info(
                    'Extracted partition %s to %s', partition_name, output_path
                )
                saved_paths.append(output_path)
            except (FileNotFoundError, PermissionError) as e:
                self.logger.error(
                    'Failed to extract partition %s: %s', partition_name, e
                )

        return saved_paths

    def analyze_image(self) -> dict[str, Any]:
        """
        Perform analysis on the bootloader image.

        Gathers statistics and information about the image structure.

        Returns:
            Dictionary containing analysis results
        """
        if not self.image:
            return {'error': 'No image loaded'}

        partition_info = []
        total_size = len(self.image.contents) if self.image.contents else 0

        for name, partition in self.image.partitions.items():
            partition_info.append(
                {
                    'name': name,
                    'size': len(partition.data),
                    'has_ext_header': partition.header.is_extended,
                    'memory_address': f'0x{partition.header.memory_address:08x}',
                }
            )

        return {
            'image_path': str(self.image.path)
            if self.image.path
            else 'Unknown',
            'image_version': self.image.version,
            'image_size': total_size,
            'partition_count': len(self.image.partitions),
            'partitions': partition_info,
        }
