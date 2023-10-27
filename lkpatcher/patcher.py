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

import json
import logging

from pathlib import Path
from liblk.LkImage import LkImage
from liblk.Exceptions import NeedleNotFoundException

from lkpatcher.exceptions import InvalidIOFile, NoNeedlesFound

class PatchManager:
    """
    A class representing a patch manager.

    It can be used to manage and load patches
    from a json file.
    """
    DEFAULT_PATCHES = {
        # Unlock fastboot access by forcing the function
        # that checks for the unlock bit in oplusreserve
        # to always return 0 (unlocked).
        "fastboot": {
            "2de9f04fadf5ac5d": "00207047",
            "f0b5adf5925d": "00207047",
        },

        # Disable the annoying warning message that shows
        # up when the device gets unlocked with mtkclient.
        # This is done by forcing the function that checks
        # for the current vbmeta state to always return 0.
        "dm_verity": {
            "30b583b002ab0022": "00207047",
        },

        # Disable the annoying warning message that shows
        # up when the device gets unlocked with any method.
        # This is done by forcing the function that checks
        # for the current LCS state to always return 0.
        "orange_state": {
            "08b50a4b7b441b681b68022b": "00207047",
        },

        # This shouldn't be necessary, but regardless, it
        # forces the function that prints the warning in
        # regard to the device's verification.
        "red_state": {
            "f0b5002489b0": "00207047",
        },
    }

    def __init__(self, patches: Path = None) -> None:
        """
        Initialize a PatchManager object.
        :param patches: Path to the json file with patches.
        """
        self.logger = logging.getLogger(__name__)
        self.patches: dict = self.DEFAULT_PATCHES

        if patches:
            self.load_patches(patches)

        self.patches_count = len(self.get_patches(self.patches))
        self.logger.info(f'Successfully loaded {self.patches_count} patches.')

    def load_patches(self, file: Path) -> None:
        """
        Load patches from a json file.
        :param file: Path to the json file with patches.
        :return: None
        """
        try:
            with open(file, 'r') as fp:
                self.patches = json.load(fp)
        except FileNotFoundError as e:
            self.logger.warning(f'Unable to load patches from {file}: {e.strerror}!')
        except json.JSONDecodeError as e:
            raise InvalidIOFile(e.msg, file)

    @classmethod
    def get_patches(cls, patches: dict) -> list:
        """
        Get a list of all the patches.
        :param patches: A dict with all the patches.
        :return: A list with all the patches.
        """
        return [key for sub_dict in patches.values() for key in sub_dict.keys()]

class LkPatcher:
    """
    A class representing a LK patcher.

    As the name suggests, it can be used to
    patch MediaTek bootloaders (LK). Custom
    patches can be also loaded from a json
    file.
    """
    def __init__(self, image: Path, patches: Path = None) -> None:
        """
        Initialize a LkPatcher object.
        :param image: Path to the bootloader image.
        """
        self.logger = logging.getLogger(__name__)
        self.patch_manager = PatchManager(patches)
        self.image: LkImage = LkImage(image)

    def patch(self, output: Path) -> Path:
        """
        Patch the bootloader image.
        :param output: Path to the output patched image.
        :param json: If specified, the patches will be loaded
        from this json file.
        :return: If successful, the path to the patched image.
        """
        # Retrieve the available patches from the patch manager.
        available_patches = self.patch_manager.patches.items()

        # Iterate over the available patches and apply them.
        for category, patches in list(available_patches):
            for needle, patch in list(patches.items()):
                try:
                    # Use the LkImage object to apply the patch
                    # and remove it from the available patches.
                    self.image.apply_patch(needle, patch)
                    del self.patch_manager.patches[category][needle]
                except NeedleNotFoundException:
                    # This is fine, not all the patches are present
                    # in all the bootloaders. Just skip it and move on.
                    self.logger.warning(f'Skipping invalid needle {needle}.')

        # Compare the size of the available patches with the original
        # size of the patches. If they're the same, it means we could
        # not apply any patch.
        available_patches = -(len(self.patch_manager.get_patches(
                                self.patch_manager.patches)) -
                             self.patch_manager.patches_count)
        if available_patches == 0:
            # No patches were applied, dump LK info and raise an exception.
            with open(f'{self.image.lk_path}.txt', 'w') as fp:
                for partition in self.image.get_partition_list():
                    fp.write(f'{partition}:\n'
                             f'{str(self.image.get_partition_by_name(partition))}\n\n')
            raise NoNeedlesFound(f'No needles found in {self.image.lk_path}.')

        # Lastly, write the patched image to the output file and handle
        # any possible exception(s).
        try:
            with open(output, 'wb') as fp:
                fp.write(self.image.lk_contents)
        except FileNotFoundError as e:
            raise InvalidIOFile(e.strerror, output)
        except PermissionError as e:
            raise InvalidIOFile(e.strerror, output)

        # Return the path to the patched image.
        self.logger.info(f'Successfully applied {available_patches} patches.')
        return output

    def dump_partition(self, partname):
        '''
        Dump a partition from the bootloader image.
        :param partname: Name of the partition to dump.
        :return: None
        '''
        # Try to retrieve the partition from the image.
        partition = self.image.get_partition_by_name(partname)

        # Make sure the partition exists.
        if not partition:
            # If it doesn't, print the available partitions and return.
            self.logger.error(f'Unable to find partition {partname}!')
            self.logger.warning(f'Available partitions: '
                                f'{self.image.get_partition_list()}')
            return

        # We know the partition exists so we cant print its
        # information to the user.
        print("=====================================")
        print(str(partition))
        print("=====================================")

        # Lastly, dump the partition to a file.
        try:
            with open(f'{partname}.bin', 'wb') as fp:
                fp.write(partition.data)
        except FileNotFoundError as e:
            raise InvalidIOFile(e.strerror, partname)
        except PermissionError as e:
            raise InvalidIOFile(e.strerror, partname)

        self.logger.info(f'Successfully dumped partition '
                         f'{partname} to {partname}.bin.')