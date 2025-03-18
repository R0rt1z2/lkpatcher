# lkpatcher

![License](https://img.shields.io/github/license/R0rt1z2/lkpatcher)
![GitHub Issues](https://img.shields.io/github/issues-raw/R0rt1z2/lkpatcher?color=red)

`lkpatcher` is a comprehensive Python tool and module designed for modifying and patching LK (_Little Kernel_) bootloader images. The utility offers flexibility along with an intuitive API for maximum control.

To use the library, **Python 3.8** or higher is required. An alternative method is available via the [web version](https://lkpatcher.r0rt1z2.com/), which is not open-source but offers the same functionality with a GUI.

## Installation

```bash
sudo apt install python3-pip # If you don't have pip installed.
pip3 install --upgrade pip   # If pip hasn't been updated yet.
pip3 install --upgrade git+https://github.com/R0rt1z2/lkpatcher
```
> <small>[!NOTE]
> _Windows users should omit the first two command(s) and install Python manually from [here](https://www.python.org/downloads/)._</small>

## Basic Usage

```bash
python3 -m lkpatcher [-h] [options] bootloader_image
```

### Command-line Options

#### Main Options:
```
-o, --output FILE           Path to the output patched image
-c, --config FILE           Path to configuration file (JSON)
-j, --json-patches FILE     Path to JSON file with custom patches
```

#### Operational Modes:
```
-l, --list-partitions       List all partitions in the bootloader image
-d, --dump-partition NAME   Dump partition with NAME to a file
-i, --partition-info NAME   Display detailed information about partition NAME
--dry-run                   Perform a dry run without writing changes
--export-config FILE        Export default configuration to FILE and exit
```

#### Patch Control:
```
--category CATEGORY         Patch category to apply (can be used multiple times)
--exclude CATEGORY          Patch category to exclude (can be used multiple times)
```

#### Backup Options:
```
--backup                    Create a backup before patching
--backup-dir DIR            Directory to store backups
```

#### Logging Options:
```
--log-level LEVEL           Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
--log-file FILE             Log to specified file in addition to console
```

#### Miscellaneous:
```
-v, --version               Show version information and exit
-h, --help                  Show help message and exit
```

### Examples:

```bash
# Basic patching with default settings
python3 -m lkpatcher lk.img

# Specify output file
python3 -m lkpatcher lk.img -o patched.img

# Use custom configuration and patches
python3 -m lkpatcher lk.img -c config.json -j patches.json

# List partitions in an image
python3 -m lkpatcher lk.img --list-partitions

# Dump a specific partition
python3 -m lkpatcher lk.img -d lk

# Apply only specific patch categories
python3 -m lkpatcher lk.img --category fastboot --category dm_verity

# Export default configuration
python3 -m lkpatcher --export-config config.json
```

## Using as a Library

You can use lkpatcher in your own projects:

```python
from lkpatcher.patcher import LkPatcher
from lkpatcher.config import PatcherConfig

# Create a custom configuration (optional)
config = PatcherConfig()
config.log_level = "DEBUG"
config.backup = True
config.patch_categories = {"fastboot", "dm_verity"}  # Only apply these categories

# Create the patcher object
patcher = LkPatcher(
    image='lk.img',
    patches='patches.json',
    config=config
)

# List available partitions
partitions = patcher.image.get_partition_list()
print(f"Available partitions: {partitions}")

# Apply patches and save the result
output_path = patcher.patch(output='lk-patched.bin')

# Extract all partitions to a directory
patcher.extract_all_partitions("partitions_dir")

# Analyze the image
analysis = patcher.analyze_image()
print(analysis)
```

## Patch Files

Patch files are JSON files containing categories of binary patches to apply. Each patch consists of a "needle" (bytes to find) and a "patch" (replacement bytes).

Example patch file:
```json
{
    "mode": "update",
    "fastboot": {
        "2de9f04fadf5ac5d": "00207047"
    },
    "dm_verity": {
        "30b583b002ab0022": "00207047"
    }
}
```

The `mode` can be:
- `update`: Add/update patches while keeping defaults (default)
- `replace`: Replace all default patches with only those in the file

## Configuration

You can customize behavior through a JSON configuration file:

```json
{
    "log_level": "INFO",
    "backup": true,
    "backup_dir": "./backups",
    "verify_patch": true,
    "allow_incomplete": true,
    "dry_run": false,
    "patch_categories": ["fastboot", "dm_verity"],
    "exclude_categories": []
}
```

## Important Notes

- To successfully boot patched images, unlock **seccfg** using [mtkclient](https://github.com/bkerler/mtkclient).
- Create backups of your existing images before patching. You are responsible for any damage to your device.
- If your device doesn't boot after unlocking with mtkclient, it likely uses SBC and is not supported.
- For debugging issues, dump the `expdb` partition with mtkclient and open a new issue with the dump attached.
- For device-specific patch requests, open a new issue with your LK image and the generated `image.txt` file.
- To learn how these patches work and create your own, see the [guide](https://blog.r0rt1z2.com/patch-mediatek-bootloader-images-lk.html).

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](https://github.com/R0rt1z2/lkpatcher/tree/master/LICENSE) file for details.
