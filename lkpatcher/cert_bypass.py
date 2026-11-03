"""
SPDX-FileCopyrightText: 2025-2026 Roger Ortiz <me@r0rt1z2.com>
SPDX-License-Identifier: GPL-3.0-or-later
"""

from __future__ import annotations

import logging
from enum import Enum

from liblk.image import LkImage
from liblk.structures.certificate import Certificate
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.univ import BitString

logger = logging.getLogger(__name__)


class CertBypassMode(str, Enum):
    """Strategy used to forge a bypassing ``cert2``."""

    #: Wrap the signed cert in a BIT STRING, append a copy with new hashes.
    WRAP = 'wrap'
    #: Prepend a ``[0]`` hash-override block before the untouched signed cert.
    OVERRIDE = 'override'


def build_bypass_cert2_wrap(
    original_cert2: bytes, header_hash: bytes, image_hash: bytes
) -> bytes:
    """
    Build a bypassing ``cert2`` using the wrap strategy.

    Args:
        original_cert2: The original, validly signed ``cert2`` bytes
        header_hash: SHA-256 digest of the (patched) partition header
        image_hash: SHA-256 digest of the (patched) partition data

    Returns:
        Forged ``cert2`` bytes
    """
    cert = Certificate.from_bytes(original_cert2)

    verified_copy = der_encode(BitString(hexValue=bytes(original_cert2).hex()))
    forged_copy = cert.encode_with_hashes(header_hash, image_hash)

    return verified_copy + forged_copy


def build_bypass_cert2_override(
    original_cert2: bytes, header_hash: bytes, image_hash: bytes
) -> bytes:
    """
    Build a bypassing ``cert2`` using the override strategy.

    Instead of wrapping the signed cert in a BIT STRING, this prepends a ``[0]``
    block carrying the new hashes in front of the untouched original.

    Args:
        original_cert2: The original, validly signed ``cert2`` bytes
        header_hash: SHA-256 digest of the (patched) partition header
        image_hash: SHA-256 digest of the (patched) partition data

    Returns:
        Forged ``cert2`` bytes
    """
    cert = Certificate.from_bytes(original_cert2)
    override = cert.build_hash_override_block(header_hash, image_hash)
    return override + bytes(original_cert2)


_BUILDERS = {
    CertBypassMode.WRAP: build_bypass_cert2_wrap,
    CertBypassMode.OVERRIDE: build_bypass_cert2_override,
}


def apply_cert_bypass(
    image: LkImage, mode: CertBypassMode = CertBypassMode.OVERRIDE
) -> list[str]:
    """
    Re-sign every modified partition in an image using the cert bypass.

    A partition is considered modified when its current contents no longer
    match the hashes embedded in its ``cert2``. Unmodified partitions keep
    their original, valid certificate untouched.

    Args:
        image: Image whose partitions should be re-signed in place
        mode: Forging strategy to use (see :class:`CertBypassMode`)

    Returns:
        Names of the partitions that were re-signed
    """
    build = _BUILDERS[CertBypassMode(mode)]
    signed: list[str] = []

    for name, partition in image.partitions.items():
        if partition.cert2 is None:
            continue

        status = partition.matches_cert2()

        if status is None:
            logger.warning(
                "Partition '%s' has a cert2 that could not be parsed "
                '(already bypassed?), skipping',
                name,
            )
            continue

        if status:
            logger.debug(
                "Partition '%s' is unmodified, leaving its certificate intact",
                name,
            )
            continue

        header_hash, image_hash = partition.compute_hashes()
        original = bytes(partition.cert2.data)
        partition.cert2.data = build(original, header_hash, image_hash)

        logger.info(
            "Re-signed modified partition '%s' (%s, cert2 %d -> %d bytes)",
            name,
            CertBypassMode(mode).value,
            len(original),
            len(partition.cert2.data),
        )
        signed.append(name)

    if signed:
        image._rebuild_contents()

    return signed
