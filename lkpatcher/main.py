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

import logging

from argparse import ArgumentParser
from pathlib import Path

from lkpatcher import __version__ as version, current_path
from lkpatcher.patcher import LkPatcher

logging.basicConfig(level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S',
                    format='[%(name)s] [%(levelname)s] [%(asctime)s] %(message)s')

def main():
    logging.info("MediaTek bootloader (LK) patcher - "
                 "version: %s by R0rt1z2.", version)

    parser = ArgumentParser(prog='python3 -m lk_patcher',
                            description='Oplus bootloader patcher')

    # Main LkPatcher arguments (bootloader image).
    parser.add_argument('bootloader_image', type=Path,
                        help='Path to the bootloader image to patch.')

    # Optional LkPatcher arguments (output patched image, json).
    parser.add_argument('-o', '--output', type=Path,
                        default=f'{current_path}/lk-patched.img',
                        help='Path to the output patched image.')
    parser.add_argument('-j', '--json', type=Path,
                        help='Path to the json file with patches.')

    # Secondary LkPatcher arguments (dumping).
    parser.add_argument('-d', '--dump-partition', type=str,
                        help='Name of the partition to dump.')

    args = parser.parse_args()
    patcher = LkPatcher(image=args.bootloader_image, patches=args.json)

    if args.dump_partition:
        return patcher.dump_partition(args.dump_partition)

    image = patcher.patch(args.output)
    logging.info("Patched image saved to %s.", image)