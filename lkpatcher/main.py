"""
SPDX-FileCopyrightText: 2025 Roger Ortiz <me@r0rt1z2.com>
SPDX-License-Identifier: GPL-3.0-or-later
"""

from __future__ import annotations

import json
import logging
import shutil
import sys
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from datetime import datetime
from pathlib import Path

from liblk.structures.partition import LkPartition

from lkpatcher import (
    __author__,
    __description__,
    __version__,
)
from lkpatcher.cert_bypass import CertBypassMode
from lkpatcher.config import LogLevel, PatcherConfig
from lkpatcher.exceptions import (
    ConfigurationError,
    InvalidIOFile,
    LkPatcherError,
)
from lkpatcher.patcher import LkPatcher
from lkpatcher.policy import analyze_lk_security_policies


def setup_logging(log_level: LogLevel, log_file: Path | None = None) -> None:
    """
    Set up logging configuration.

    Args:
        log_level: Logging level to use
        log_file: Optional file to log to in addition to console
    """
    handlers: list[logging.Handler] = [logging.StreamHandler()]

    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            handlers.append(file_handler)
        except OSError as e:
            print(f'Warning: Could not create log file ({e})', file=sys.stderr)

    logging.basicConfig(
        level=log_level.to_logging_level(),
        format='[%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=handlers,
    )


def create_backup(image_path: Path, backup_dir: Path | None = None) -> Path:
    """
    Create a backup of the original image.

    Args:
        image_path: Path to the image to back up
        backup_dir: Optional directory to store backup in

    Returns:
        Path to the backup file

    Raises:
        InvalidIOFile: If backup creation fails
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_name = f'{image_path.stem}_backup_{timestamp}{image_path.suffix}'

    if backup_dir:
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / backup_name
    else:
        backup_path = image_path.parent / backup_name

    try:
        shutil.copy2(image_path, backup_path)
        return backup_path
    except OSError as e:
        raise InvalidIOFile(str(e), backup_path)


def list_partitions(patcher: LkPatcher) -> None:
    """
    List all partitions in the bootloader image.

    Args:
        patcher: LkPatcher instance
    """
    partitions = patcher.image.partitions
    if not partitions:
        print('No partitions found in image.')
        return

    print('\nPartitions in bootloader image:')
    print('-' * 40)
    for i, (name, partition) in enumerate(partitions.items(), 1):
        print(f'{i}. {name} ({len(partition.data)} bytes)')
    print('-' * 40)


def analyze_security_policies(patcher: LkPatcher) -> None:
    """
    Analyze security policies in the LK partition.

    Args:
        patcher: LkPatcher instance
    """
    lk_partition = patcher.image.partitions.get('lk')
    if not lk_partition:
        print('Error: No LK partition found in image.')
        return

    try:
        results = analyze_lk_security_policies(lk_partition)

        if 'warning' in results:
            print(f'Warning: {results["warning"]}')

        if results['policy_table_found']:
            print(f'Policy Table Offset: {results["policy_table_offset"]}')
            print('Security Policies:')
            print('-' * 50)
            print(
                'Policy Name      nosbc+lock  nosbc+unlock  sbc+lock  sbc+unlock'
            )
            print('-' * 50)
            for policy in results['policies']:
                print(
                    f'{policy["name"]:<12}: {policy["nosbc_lock"]:<10} {policy["nosbc_unlock"]:<12} {policy["sbc_lock"]:<8} {policy["sbc_unlock"]}'
                )
        else:
            print('No security policy table found.')

        print('=' * 50)

    except Exception as e:  # noqa: BLE001 - report and keep going
        print(f'Error analyzing security policies: {e}')


def export_config(patcher: LkPatcher, output_path: Path) -> None:
    """
    Export default configuration to a file.

    Args:
        patcher: LkPatcher instance
        output_path: Path to save configuration to
    """
    config = PatcherConfig()

    patch_info = {
        'available_patches': {
            category: list(patches.keys())
            for category, patches in patcher.patch_manager.patches.items()
        }
    }

    combined_data = {**config.to_dict(), **patch_info}

    try:
        with open(output_path, 'w') as f:
            json.dump(combined_data, f, indent=4)
        print(f'Configuration exported to {output_path}')
    except OSError as e:
        print(f'Error exporting configuration: {e}', file=sys.stderr)


def display_partition_info(partition: LkPartition) -> None:
    """
    Display detailed information about a partition.

    Args:
        partition: Partition to display information for
    """
    print('\nPartition Details:')
    print('=' * 60)
    print(str(partition))
    print('\nData Information:')
    print('-' * 60)
    print(f'Size: {len(partition)} bytes')

    preview_size = min(64, len(partition.data))
    hex_preview = ' '.join(f'{b:02x}' for b in partition.data[:preview_size])
    print(
        f'Data preview: {hex_preview}{"..." if len(partition.data) > preview_size else ""}'
    )
    print('=' * 60)


def add_partition_to_image(
    patcher: LkPatcher,
    partition_name: str,
    data_file: Path,
    memory_address: int = 0,
    use_extended: bool = True,
) -> None:
    """
    Add a new partition to the LK image.

    Args:
        patcher: LkPatcher instance
        partition_name: Name for the new partition
        data_file: Path to file containing partition data
        memory_address: Load address for the partition
        use_extended: Use extended header format
    """
    if not data_file.exists():
        raise InvalidIOFile(f'Data file not found: {data_file}', data_file)

    with open(data_file, 'rb') as f:
        partition_data = f.read()

    patcher.image.add_partition(
        name=partition_name,
        data=partition_data,
        memory_address=memory_address,
        use_extended=use_extended,
    )

    print(f'Added partition: {partition_name} ({len(partition_data)} bytes)')


def replace_partition_in_image(
    patcher: LkPatcher,
    partition_name: str,
    data_file: Path,
    memory_address: int | None = None,
) -> bool:
    """
    Replace an existing partition data in the LK image.

    Args:
        patcher: LkPatcher instance
        partition_name: Name of target partition
        data_file: Path to file containing new partition data
        memory_address: Optional memory address for the partition

    Returns:
        True if replaced successfully, False otherwise
    """
    if not data_file.exists():
        raise InvalidIOFile(f'Data file not found: {data_file}', data_file)

    if partition_name not in patcher.image.partitions:
        print(f'Error: Partition not found: {partition_name}')
        list_partitions(patcher)
        return False

    with open(data_file, 'rb') as f:
        partition_data = f.read()

    patcher.replace_partition(
        name=partition_name,
        data=partition_data,
        memory_address=memory_address,
    )

    print(f'Replaced partition: {partition_name} ({len(partition_data)} bytes)')
    return True


def remove_partition_from_image(
    patcher: LkPatcher, partition_name: str
) -> None:
    """
    Remove a partition from the LK image.

    Args:
        patcher: LkPatcher instance
        partition_name: Name of partition to remove
    """
    if partition_name not in patcher.image.partitions:
        print(f'Error: Partition not found: {partition_name}')
        list_partitions(patcher)
        return

    patcher.image.remove_partition(partition_name)
    print(f'Removed partition: {partition_name}')


def add_certificate_to_partition(
    patcher: LkPatcher,
    partition_name: str,
    cert_file: Path,
    cert_type: str = 'cert1',
) -> None:
    """
    Add a certificate to a partition.

    Args:
        patcher: LkPatcher instance
        partition_name: Name of target partition
        cert_file: Path to certificate file
        cert_type: Certificate type ('cert1' or 'cert2')
    """
    if not cert_file.exists():
        raise InvalidIOFile(
            f'Certificate file not found: {cert_file}', cert_file
        )

    if partition_name not in patcher.image.partitions:
        print(f'Error: Partition not found: {partition_name}')
        list_partitions(patcher)
        return

    with open(cert_file, 'rb') as f:
        cert_data = f.read()

    partition = patcher.image.partitions[partition_name]
    partition.add_certificate(cert_data, cert_type)
    patcher.image._rebuild_contents()

    print(
        f'Added {cert_type} to partition {partition_name} ({len(cert_data)} bytes)'
    )


def main() -> int:
    """
    Main entry point for the LK patcher application.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    parser = ArgumentParser(
        prog='python3 -m lkpatcher',
        description=f'{__description__} v{__version__}\nBy {__author__}',
        formatter_class=RawDescriptionHelpFormatter,
        epilog='Examples:\n'
        '  %(prog)s lk.img                       # Patch with default settings\n'
        '  %(prog)s lk.img -o patched.img        # Specify output file\n'
        '  %(prog)s lk.img -c mypatches.json     # Use custom config\n'
        '  %(prog)s lk.img --list-partitions     # List image partitions\n'
        "  %(prog)s lk.img -d lk                 # Dump 'lk' partition\n"
        '  %(prog)s lk.img --analyze-policies    # Analyze security policies\n'
        '  %(prog)s --export-config config.json  # Export default config\n'
        '  %(prog)s lk.img --add-partition custom data.bin  # Add partition\n'
        '  %(prog)s lk.img --replace-partition lk u-boot.bin # Replace partition\n'
        '  %(prog)s lk.img --remove-partition unwanted      # Remove partition',
    )

    parser.add_argument(
        'bootloader_image',
        type=Path,
        nargs='?',
        help='Path to the bootloader image to patch',
    )
    parser.add_argument(
        '-o',
        '--output',
        type=Path,
        help='Path to the output patched image (default: [original]-patched.img)',
    )

    parser.add_argument(
        '-c', '--config', type=Path, help='Path to configuration file (JSON)'
    )
    parser.add_argument(
        '-j',
        '--json-patches',
        type=Path,
        help='Path to JSON file with custom patches',
    )
    parser.add_argument(
        '--export-config',
        type=Path,
        metavar='FILE',
        help='Export default configuration to FILE and exit',
    )

    group = parser.add_argument_group('Operational Modes')
    group.add_argument(
        '-l',
        '--list-partitions',
        action='store_true',
        help='List all partitions in the bootloader image',
    )
    group.add_argument(
        '-d',
        '--dump-partition',
        type=str,
        metavar='NAME',
        help='Dump partition with NAME to a file',
    )
    group.add_argument(
        '-i',
        '--partition-info',
        type=str,
        metavar='NAME',
        help='Display detailed information about partition NAME',
    )
    group.add_argument(
        '--analyze-policies',
        action='store_true',
        help='Analyze security policies in the LK partition',
    )
    group.add_argument(
        '--cert-bypass',
        nargs='?',
        const='override',
        choices=['wrap', 'override'],
        default=None,
        metavar='MODE',
        help='Re-sign modified partitions with the cert bypass '
        "(MODE: 'override' (default) or 'wrap')",
    )
    group.add_argument(
        '--dry-run',
        action='store_true',
        help='Perform a dry run without writing changes',
    )

    partition_group = parser.add_argument_group('Partition Management')
    partition_group.add_argument(
        '--add-partition',
        nargs=2,
        metavar=('NAME', 'DATA_FILE'),
        help='Add new partition with NAME from DATA_FILE',
    )
    partition_group.add_argument(
        '--replace-partition',
        nargs=2,
        metavar=('NAME', 'DATA_FILE'),
        help='Replace partition with NAME from DATA_FILE',
    )
    partition_group.add_argument(
        '--remove-partition',
        metavar='NAME',
        help='Remove partition with NAME',
    )
    partition_group.add_argument(
        '--add-certificate',
        nargs=2,
        metavar=('PARTITION', 'CERT_FILE'),
        help='Add certificate from CERT_FILE to PARTITION',
    )
    partition_group.add_argument(
        '--partition-address',
        type=lambda x: int(x, 0),
        default=None,
        help='Memory address for new or replaced partition (hex or decimal)',
    )
    partition_group.add_argument(
        '--partition-legacy',
        action='store_true',
        help='Use legacy header format for new partitions',
    )
    partition_group.add_argument(
        '--cert-type',
        choices=['cert1', 'cert2'],
        default='cert1',
        help='Certificate type for --add-certificate (default: cert1)',
    )

    patch_group = parser.add_argument_group('Patch Control')
    patch_group.add_argument(
        '--category',
        action='append',
        dest='categories',
        help='Patch category to apply (can be used multiple times)',
    )
    patch_group.add_argument(
        '--exclude',
        action='append',
        dest='exclude_categories',
        help='Patch category to exclude (can be used multiple times)',
    )
    patch_group.add_argument(
        '--patch-policies',
        action='store_true',
        help='Patch security policies to disable verification',
    )

    backup_group = parser.add_argument_group('Backup Options')
    backup_group.add_argument(
        '--backup', action='store_true', help='Create a backup before patching'
    )
    backup_group.add_argument(
        '--backup-dir', type=Path, help='Directory to store backups'
    )

    log_group = parser.add_argument_group('Logging Options')
    log_group.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set logging level',
    )
    log_group.add_argument(
        '--log-file',
        type=Path,
        help='Log to specified file in addition to console',
    )

    parser.add_argument(
        '-v', '--version', action='version', version=f'%(prog)s {__version__}'
    )

    args = parser.parse_args()

    if args.export_config:
        if not args.bootloader_image:
            dummy_patcher = LkPatcher(Path('dummy'), load_image=False)
            export_config(dummy_patcher, args.export_config)
            return 0
        else:
            try:
                patcher = LkPatcher(
                    args.bootloader_image, args.json_patches, load_image=True
                )
                export_config(patcher, args.export_config)
                return 0
            except LkPatcherError as e:
                print(f'Error: {e}', file=sys.stderr)
                return 1

    if not args.bootloader_image:
        if any(
            [
                args.list_partitions,
                args.dump_partition,
                args.partition_info,
                args.analyze_policies,
                args.add_partition,
                args.replace_partition,
                args.remove_partition,
                args.add_certificate,
                args.cert_bypass,
                args.output,
            ]
        ):
            parser.error('bootloader_image is required')
            return 1
        else:
            parser.print_help()
            return 0

    config = PatcherConfig()
    if args.config:
        try:
            config = PatcherConfig.from_file(args.config)
        except ConfigurationError as e:
            print(f'Configuration error: {e}', file=sys.stderr)
            return 1

    config.log_level = LogLevel.from_string(args.log_level)
    config.backup = args.backup
    if args.backup_dir:
        config.backup_dir = args.backup_dir
    config.dry_run = args.dry_run

    if args.categories:
        config.patch_categories = set(args.categories)
    if args.exclude_categories:
        config.exclude_categories = set(args.exclude_categories)

    setup_logging(config.log_level, args.log_file)
    logger = logging.getLogger(__name__)

    logger.info(
        'MediaTek bootloader (LK) patcher - version: %s by R0rt1z2', __version__
    )

    try:
        patcher = LkPatcher(
            args.bootloader_image, args.json_patches, config=config
        )

        partition_modified = False

        if args.list_partitions:
            list_partitions(patcher)
            return 0

        if args.analyze_policies:
            analyze_security_policies(patcher)
            return 0

        if args.partition_info:
            partition = patcher.image.partitions.get(args.partition_info)
            if partition:
                display_partition_info(partition)
            else:
                logger.error('Partition not found: %s', args.partition_info)
                list_partitions(patcher)
                return 1
            return 0

        if args.dump_partition:
            result = patcher.dump_partition(args.dump_partition)
            return 0 if result else 1

        if args.add_partition:
            partition_name, data_file = args.add_partition
            add_partition_to_image(
                patcher,
                partition_name,
                Path(data_file),
                args.partition_address
                if args.partition_address is not None
                else 0,
                not args.partition_legacy,
            )
            partition_modified = True

        if args.replace_partition:
            partition_name, data_file = args.replace_partition
            if not replace_partition_in_image(
                patcher,
                partition_name,
                Path(data_file),
                args.partition_address,
            ):
                return 1
            partition_modified = True

        if args.remove_partition:
            remove_partition_from_image(patcher, args.remove_partition)
            partition_modified = True

        if args.add_certificate:
            partition_name, cert_file = args.add_certificate
            add_certificate_to_partition(
                patcher, partition_name, Path(cert_file), args.cert_type
            )
            partition_modified = True

        if args.output:
            output_path = args.output
        elif args.cert_bypass is not None:
            output_path = args.bootloader_image.with_stem(
                f'{args.bootloader_image.stem}-signed'
            )
        else:
            suffix = '-modified' if partition_modified else '-patched'
            output_path = args.bootloader_image.with_stem(
                f'{args.bootloader_image.stem}{suffix}'
            )

        if config.backup and not config.dry_run:
            backup_path = create_backup(
                args.bootloader_image, config.backup_dir
            )
            logger.info('Created backup at %s', backup_path)

        if args.cert_bypass is not None:
            mode = CertBypassMode(args.cert_bypass)

            if config.dry_run:
                logger.info(
                    'Dry run: would re-sign (%s) and save to %s',
                    mode.value,
                    output_path,
                )
                return 0

            signed = patcher.apply_cert_bypass(mode)
            if signed:
                logger.info(
                    'Applied cert bypass (%s) to: %s',
                    mode.value,
                    ', '.join(signed),
                )
            else:
                logger.info(
                    'Cert bypass requested, but nothing needed re-signing'
                )

            patcher.image.save(output_path)
            logger.info('Re-signed image saved to %s', output_path)
            return 0

        if partition_modified:
            if not config.dry_run:
                patcher.image.save(output_path)
                logger.info('Modified image saved to %s', output_path)
            else:
                logger.info(
                    'Dry run: would save modified image to %s', output_path
                )
        else:
            patched_path = patcher.patch(
                output_path,
                patch_policies=args.patch_policies,
            )
            logger.info('Patched image saved to %s', patched_path)

        return 0

    except LkPatcherError as e:
        logger.error(str(e))
        return 1
    except Exception:
        logger.exception('Unexpected error')
        return 1


if __name__ == '__main__':
    sys.exit(main())
