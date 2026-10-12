#!/usr/bin/env python3
"""Reference implementation helpers for the yEnc encryption standards v1.2.

This module is the canonical executable statement of the derivations that
implementations must reproduce:

- Argon2id key derivation with the exact v1.2 KDF inputs (UTF-8 password
  encoding with no normalization, v=0x13, t=1, m=65536 KiB, p=4, 32-byte
  output, empty optional secret/AD).
- Body nonce derivation (Body Standard Section 4).
- Associated Data (AAD) serialization exactly per Body Standard Section 2.1.
- Body encryption/decryption with that AAD (Section 4 / Section 5).
- Control-line FF1 key and tweak derivation (Control Lines Standard
  Section 4) and the deterministic combined-mode restoration rule
  (Control Lines Standard Section 5, step 4).

Nothing in this module is an optimization target; clarity and exact
agreement with the normative text are the only goals.
"""

import hashlib
import hmac
import struct

import argon2.low_level as ll
import nacl.bindings as nb

# Exact v1.2 KDF parameters (Body Standard Section 4 / Control Lines
# Standard Section 4).
ARGON2ID_VERSION = 0x13  # decimal 19
ARGON2ID_TIME_COST = 1
ARGON2ID_MEMORY_COST_KIB = 65536  # 64 MiB
ARGON2ID_PARALLELISM = 4
ARGON2ID_HASH_LEN = 32

AAD_PREFIX = b"yenc-body aad"  # exactly 13 bytes (Body Standard Section 2.1)


def uint32_be(val: int) -> bytes:
    """Serialize 32-bit unsigned integer in big-endian network byte order."""
    if not (0 <= val <= 0xFFFFFFFF):
        raise ValueError(f"Value {val} out of range for uint32_be")
    return struct.pack(">I", val)


def uint64_be(val: int) -> bytes:
    """Serialize 64-bit unsigned integer in big-endian network byte order."""
    if not (0 <= val <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError(f"Value {val} out of range for uint64_be")
    return struct.pack(">Q", val)


def kdf_password_bytes(password: str) -> bytes:
    """Encode the password to UTF-8 with NO normalization (v1.2 Section 4).

    The normative rule is byte-level identity of the UTF-8 encoding of the
    exact code-point sequence supplied; this function deliberately performs
    no NFC/NFD/NFKC/NFKD folding.
    """
    return password.encode("utf-8")


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive the 32-byte Argon2id key with the exact v1.2 parameters."""
    return ll.hash_secret_raw(
        secret=kdf_password_bytes(password),
        salt=salt,
        time_cost=ARGON2ID_TIME_COST,
        memory_cost=ARGON2ID_MEMORY_COST_KIB,
        parallelism=ARGON2ID_PARALLELISM,
        hash_len=ARGON2ID_HASH_LEN,
        type=ll.Type.ID,
        version=ARGON2ID_VERSION,
    )


def derive_body_nonce(body_key: bytes, segment_index: int) -> bytes:
    """Derive the 24-byte body nonce: HMAC-SHA256(key, prefix || uint32_be)[0:24]."""
    message = b"yenc-body nonce" + uint32_be(segment_index)
    return hmac.new(body_key, message, hashlib.sha256).digest()[:24]


def build_aad(
    name_bytes: bytes,
    part_number: int,
    part_begin: int,
    segment_bytes: int,
) -> bytes:
    """Serialize the Associated Data exactly per Body Standard Section 2.1.

    Fixed layout:
      "yenc-body aad" || uint32_be(partNumber) || uint32_be(partBegin) ||
      uint64_be(segmentBytes) || uint32_be(nameLength) || nameBytes
    """
    if not name_bytes:
        raise ValueError("AAD subject must be non-empty; empty AAD is invalid")
    return (
        AAD_PREFIX
        + uint32_be(part_number)
        + uint32_be(part_begin)
        + uint64_be(segment_bytes)
        + uint32_be(len(name_bytes))
        + name_bytes
    )


def body_encrypt(plaintext: bytes, key: bytes, nonce: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt payload with XChaCha20-Poly1305 and the Section 2.1 AAD."""
    out = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return out[:-16], out[-16:]


def body_decrypt(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes, aad: bytes) -> bytes:
    """Authenticate and decrypt with the Section 2.1 AAD; raises on failure.

    The caller must treat a raised error as PROVIDER_FAILOVER and must
    release zero bytes (Body Standard Section 5 zero-output rule); this
    function never returns partial plaintext.
    """
    return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext + tag, aad, nonce, key
    )


def derive_control_keys(master_key: bytes, segment_index: int, line_index: int):
    """Derive the 32-byte FF1 encKey and 8-byte tweak (Control Std Section 4)."""
    enc_key = hmac.new(master_key, b"yenc-control key", hashlib.sha256).digest()
    tweak_msg = b"yenc-control tweak" + uint32_be(segment_index) + uint32_be(line_index)
    tweak = hmac.new(master_key, tweak_msg, hashlib.sha256).digest()[:8]
    return enc_key, tweak


def ybegin_is_multipart(ybegin_line: str) -> bool:
    """True when a part= keyword appears before name= (Body Std Section 3).

    name= is the last =ybegin keyword and its value runs to the end of the
    line, so a part= inside the file name never makes an article multipart.
    """
    name_pos = ybegin_line.find(" name=")
    keywords = ybegin_line if name_pos == -1 else ybegin_line[:name_pos]
    return any(token.startswith("part=") for token in keywords.split(" ")[1:])


def combined_mode_layout(ybegin_line: str) -> dict:
    """Return the deterministic combined-mode layout (Control Std Section 5 step 4).

    The layout is inferred from the restored =ybegin line only; data lines
    are never inspected. For v1.2 combined mode:
      single-part: header lines 1..2, first data line D = 3
      multipart:   header lines 1..3, first data line D = 4
    """
    if ybegin_is_multipart(ybegin_line):
        return {"multipart": True, "header_line_indices": [1, 2, 3], "first_data_line": 4}
    return {"multipart": False, "header_line_indices": [1, 2], "first_data_line": 3}
