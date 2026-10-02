#!/usr/bin/env python3
"""Deterministic conformance test vector generator for yEnc encryption standards v1.1.

Produces canonical, machine-readable JSON fixtures for:
- VEC-01: Argon2id key derivation (argon2id.json)
- VEC-02: HMAC-SHA256 nonce and tweak derivations (nonce_tweak.json)
- VEC-03: XChaCha20-Poly1305 body AEAD round-trips (body_encryption.json)
- VEC-04: NIST SP 800-38G FF1 control-line encryption round-trips (control_line_encryption.json)
- VEC-05: Malformed-input and negative rejection vectors (malformed_inputs.json)
- SHA-256 integrity manifest (manifest.json)
"""

import hashlib
import hmac
import json
import math
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
import xml.sax.saxutils as saxutils
from pathlib import Path

import argon2.low_level as ll
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import nacl.bindings as nb
import nacl.exceptions as ne

# ---------------------------------------------------------------------------
# Cryptographic Primitives & Derivations
# ---------------------------------------------------------------------------


def uint32_be(val: int) -> bytes:
    """Serialize 32-bit unsigned integer in big-endian network byte order."""
    if not (0 <= val <= 0xFFFFFFFF):
        raise ValueError(f"Value {val} out of range for uint32_be")
    return struct.pack(">I", val)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive 32-byte key using Argon2id RFC 9106 parameters."""
    return ll.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=1,
        memory_cost=65536,  # 64 MiB
        parallelism=4,
        hash_len=32,
        type=ll.Type.ID,
        version=0x13,
    )


def derive_body_nonce(body_key: bytes, segment_index: int) -> bytes:
    """Derive 24-byte nonce for XChaCha20-Poly1305 via 19-byte HMAC-SHA256 layout."""
    message = b"yenc-body nonce" + uint32_be(segment_index)
    return hmac.new(body_key, message, hashlib.sha256).digest()[:24]


def derive_control_keys(master_key: bytes, segment_index: int, line_index: int):
    """Derive 32-byte encKey and 8-byte tweak for FF1 control line encryption."""
    enc_key = hmac.new(master_key, b"yenc-control key", hashlib.sha256).digest()
    tweak_msg = b"yenc-control tweak" + uint32_be(segment_index) + uint32_be(line_index)
    tweak = hmac.new(master_key, tweak_msg, hashlib.sha256).digest()[:8]
    return enc_key, tweak


def extract_bootstrap_from_line1(line1_bytes: bytes) -> tuple[bytes, int, bytes]:
    """Extract salt (16B), uint32_be segmentIndex (4B), and ciphertext (>=2B) from Line 1."""
    if len(line1_bytes) < 22:
        raise ValueError("LINE_TRUNCATED")
    salt = line1_bytes[:16]
    for b in salt:
        if b in (0x00, 0x0A, 0x0D):
            raise ValueError("INVALID_SALT_CHARACTER")
    seg_idx = struct.unpack(">I", line1_bytes[16:20])[0]
    if seg_idx == 0:
        raise ValueError("ZERO_SEGMENT_INDEX")
    ciphertext = line1_bytes[20:]
    return salt, seg_idx, ciphertext


def validate_dual_bootstrap(line1_salt: bytes, line1_index: int, yenc_params: dict) -> bool:
    """Verify byte-for-byte salt equality and value-for-value index equality."""
    if line1_salt != yenc_params["salt"]:
        raise ValueError("DUAL_SALT_MISMATCH")
    if line1_index != yenc_params["segment_index"]:
        raise ValueError("DUAL_INDEX_MISMATCH")
    return True


# ---------------------------------------------------------------------------
# Body AEAD: XChaCha20-Poly1305
# ---------------------------------------------------------------------------


def body_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """Encrypt payload using XChaCha20-Poly1305 producing ciphertext and 16B tag."""
    ct_and_tag = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, None, nonce, key)
    ciphertext = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]
    return ciphertext, tag


def body_decrypt(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes) -> bytes:
    """Authenticate and decrypt payload; returns plaintext or raises error."""
    ct_and_tag = ciphertext + tag
    return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(ct_and_tag, None, nonce, key)


# ---------------------------------------------------------------------------
# Control Line Numeral Bijection & NIST SP 800-38G FF1 (Radix 253)
# ---------------------------------------------------------------------------


def byte_to_numeral(b: int) -> int:
    """Map byte octet to numeral 0..252 per yEnc Control Lines Standard v1.1."""
    if 0x01 <= b <= 0x09:
        return b - 1
    elif b == 0x0B:
        return 9
    elif b == 0x0C:
        return 10
    elif 0x0E <= b <= 0xFF:
        return b - 3
    raise ValueError(f"Byte 0x{b:02x} is outside the 253-byte Alphabet (0x00, 0x0A, 0x0D forbidden)")


def numeral_to_byte(i: int) -> int:
    """Map numeral 0..252 back to byte octet per yEnc Control Lines Standard v1.1."""
    if 0 <= i <= 8:
        return i + 1
    elif i == 9:
        return 0x0B
    elif i == 10:
        return 0x0C
    elif 11 <= i <= 252:
        return i + 3
    raise ValueError(f"Numeral {i} is out of range [0, 252]")


def num_radix(numerals: list[int], radix: int) -> int:
    res = 0
    for n in numerals:
        res = res * radix + n
    return res


def str_radix(val: int, radix: int, m: int) -> list[int]:
    res = [0] * m
    for i in range(m):
        res[m - 1 - i] = val % radix
        val //= radix
    return res


def cbc_mac(aes_enc, data: bytes) -> bytes:
    block = bytes(16)
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        xored = bytes(a ^ b for a, b in zip(block, chunk))
        block = aes_enc(xored)
    return block


def ff1_encrypt_numerals(key: bytes, tweak: bytes, numerals: list[int], radix: int = 253) -> list[int]:
    """NIST SP 800-38G FF1 Encryption over arbitrary numeral strings."""
    backend = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    aes_enc = backend.update
    n = len(numerals)
    t = len(tweak)
    u = n // 2
    v = n - u
    b = math.ceil(math.ceil(v * math.log2(radix)) / 8)
    d = 4 * math.ceil(b / 4) + 4

    p = bytearray(16)
    p[0], p[1], p[2] = 1, 2, 1
    p[3:6] = radix.to_bytes(3, "big")
    p[6] = 10
    p[7] = u % 256
    p[8:12] = n.to_bytes(4, "big")
    p[12:16] = t.to_bytes(4, "big")

    pad_len = ((-t - b - 1) % 16 + 16) % 16
    q_prefix = tweak + bytes(pad_len)

    A = list(numerals[:u])
    B = list(numerals[u:])

    for i in range(10):
        q = q_prefix + bytes([i]) + num_radix(B, radix).to_bytes(b, "big")
        R = cbc_mac(aes_enc, bytes(p) + q)
        S = bytearray(R)
        j = 1
        while len(S) < d:
            j_bytes = j.to_bytes(16, "big")
            blk = bytes(a ^ b for a, b in zip(R, j_bytes))
            S.extend(aes_enc(blk))
            j += 1
        y = int.from_bytes(S[:d], "big")
        m = u if i % 2 == 0 else v
        c = (num_radix(A, radix) + y) % (radix**m)
        C = str_radix(c, radix, m)
        A = B
        B = C

    return A + B


def ff1_decrypt_numerals(key: bytes, tweak: bytes, numerals: list[int], radix: int = 253) -> list[int]:
    """NIST SP 800-38G FF1 Decryption over arbitrary numeral strings."""
    backend = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    aes_enc = backend.update
    n = len(numerals)
    t = len(tweak)
    u = n // 2
    v = n - u
    b = math.ceil(math.ceil(v * math.log2(radix)) / 8)
    d = 4 * math.ceil(b / 4) + 4

    p = bytearray(16)
    p[0], p[1], p[2] = 1, 2, 1
    p[3:6] = radix.to_bytes(3, "big")
    p[6] = 10
    p[7] = u % 256
    p[8:12] = n.to_bytes(4, "big")
    p[12:16] = t.to_bytes(4, "big")

    pad_len = ((-t - b - 1) % 16 + 16) % 16
    q_prefix = tweak + bytes(pad_len)

    A = list(numerals[:u])
    B = list(numerals[u:])

    for round_idx in range(10):
        i = 9 - round_idx
        q = q_prefix + bytes([i]) + num_radix(A, radix).to_bytes(b, "big")
        R = cbc_mac(aes_enc, bytes(p) + q)
        S = bytearray(R)
        j = 1
        while len(S) < d:
            j_bytes = j.to_bytes(16, "big")
            blk = bytes(a ^ b for a, b in zip(R, j_bytes))
            S.extend(aes_enc(blk))
            j += 1
        y = int.from_bytes(S[:d], "big")
        m = u if i % 2 == 0 else v
        c = (num_radix(B, radix) - y) % (radix**m)
        C = str_radix(c, radix, m)
        B = A
        A = C

    return A + B


def ff1_encrypt(key: bytes, tweak: bytes, plaintext_bytes: bytes, radix: int = 253) -> bytes:
    """Encrypt control line byte string using FF1 over Radix 253 Alphabet."""
    numerals = [byte_to_numeral(b) for b in plaintext_bytes]
    ct_numerals = ff1_encrypt_numerals(key, tweak, numerals, radix)
    return bytes(numeral_to_byte(i) for i in ct_numerals)


def ff1_decrypt(key: bytes, tweak: bytes, ciphertext_bytes: bytes, radix: int = 253) -> bytes:
    """Decrypt control line byte string using FF1 over Radix 253 Alphabet."""
    numerals = [byte_to_numeral(b) for b in ciphertext_bytes]
    pt_numerals = ff1_decrypt_numerals(key, tweak, numerals, radix)
    return bytes(numeral_to_byte(i) for i in pt_numerals)


# ---------------------------------------------------------------------------
# Fixture Generation Functions
# ---------------------------------------------------------------------------


def generate_argon2id_vectors(path: Path):
    """Generate VEC-01 Argon2id test vectors."""
    test_cases = [
        {
            "id": "argon2id-01-basic",
            "description": "Basic alphanumeric password with 16-byte random salt from spec Section 10",
            "password": "test123",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
        },
        {
            "id": "argon2id-02-control-salt",
            "description": "Control-line 16-byte alphabet salt (ASCII 'K7mX9pL2qR8vN4wZ')",
            "password": "test123",
            "salt_hex": "4b376d5839704c32715238764e34775a",
        },
        {
            "id": "argon2id-03-complex-password",
            "description": "Password with spaces and punctuation symbols",
            "password": "P@ssw0rd with spaces & symbols!#$%",
            "salt_hex": "0102030405060708090a0b0c0d0e0f10",
        },
        {
            "id": "argon2id-04-utf8-unicode",
            "description": "UTF-8 multi-byte unicode password with emoji",
            "password": "Mötörhëad-Usenet-🔑-2026",
            "salt_hex": "fedcba98765432100123456789abcdef",
        },
        {
            "id": "argon2id-05-single-char",
            "description": "Single-character minimal password",
            "password": "a",
            "salt_hex": "ffffffffffffffffffffffffffffffff",
        },
        {
            "id": "argon2id-06-long-password",
            "description": "128-character long alphanumeric password",
            "password": "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A1b2C3d4E5f6G7h8I9j0K1l2M3n4",
            "salt_hex": "102030405060708090a0b0c0d0e0f000",
        },
    ]

    vectors = []
    for tc in test_cases:
        salt_bytes = bytes.fromhex(tc["salt_hex"])
        key = derive_key(tc["password"], salt_bytes)
        vectors.append(
            {
                "id": tc["id"],
                "description": tc["description"],
                "password": tc["password"],
                "salt_hex": tc["salt_hex"].lower(),
                "expected_key_hex": key.hex().lower(),
            }
        )

    fixture = {
        "schema_version": "1.0",
        "standard": "yEnc Body & Control Lines Encryption Standards v1.0",
        "requirement": "VEC-01",
        "parameters": {
            "algorithm": "Argon2id",
            "version": "0x13",
            "time_cost": 1,
            "memory_cost_kib": 65536,
            "parallelism": 4,
            "output_length_bytes": 32,
        },
        "vectors": vectors,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Generated {len(vectors)} Argon2id vectors in {path.name}")


def generate_nonce_tweak_vectors(path: Path):
    """Generate VEC-02 Nonce & Tweak derivation test vectors."""
    body_key = derive_key("test123", bytes.fromhex("1a2b3c4d5e6f7890abcdef1234567890"))
    master_key = derive_key("test123", bytes.fromhex("4b376d5839704c32715238764e34775a"))
    enc_key = hmac.new(master_key, b"yenc-control key", hashlib.sha256).digest()

    segment_indices = [1, 2, 255, 256, 65535, 65536, 16777215, 4294967295]
    body_vectors = []
    for idx in segment_indices:
        msg = b"yenc-body nonce" + uint32_be(idx)
        full_hmac = hmac.new(body_key, msg, hashlib.sha256).digest()
        nonce = full_hmac[:24]
        body_vectors.append(
            {
                "id": f"body-nonce-seg-{idx}",
                "description": f"Body nonce derivation for segmentIndex={idx}",
                "key_hex": body_key.hex().lower(),
                "segment_index": idx,
                "message_hex": msg.hex().lower(),
                "message_length_bytes": len(msg),
                "full_hmac_hex": full_hmac.hex().lower(),
                "expected_nonce_hex": nonce.hex().lower(),
            }
        )

    control_pairs = [
        (1, 1, "header line 1 (=ybegin)"),
        (1, 2, "header line 2 (=ypart)"),
        (1, 3, "header line 3 (=yencryption)"),
        (1, 54, "footer line (=yend for 54-line article)"),
        (2, 1, "second segment line 1 (=ybegin)"),
        (2, 4, "second segment line 4 (=yend)"),
        (65536, 1000, "high segment and line index pair"),
    ]
    control_vectors = []
    for seg_idx, line_idx, desc in control_pairs:
        tweak_msg = b"yenc-control tweak" + uint32_be(seg_idx) + uint32_be(line_idx)
        full_tweak_hmac = hmac.new(master_key, tweak_msg, hashlib.sha256).digest()
        tweak = full_tweak_hmac[:8]
        control_vectors.append(
            {
                "id": f"control-tweak-seg-{seg_idx}-line-{line_idx}",
                "description": f"Control tweak derivation for segmentIndex={seg_idx}, lineIndex={line_idx} ({desc})",
                "master_key_hex": master_key.hex().lower(),
                "enc_key_hex": enc_key.hex().lower(),
                "segment_index": seg_idx,
                "line_index": line_idx,
                "message_hex": tweak_msg.hex().lower(),
                "message_length_bytes": len(tweak_msg),
                "full_hmac_hex": full_tweak_hmac.hex().lower(),
                "expected_tweak_hex": tweak.hex().lower(),
            }
        )

    fixture = {
        "schema_version": "1.0",
        "standard": "yEnc Body & Control Lines Encryption Standards v1.0",
        "requirement": "VEC-02",
        "parameters": {
            "integer_encoding": "uint32_be (4-byte unsigned big-endian network byte order)",
            "body_nonce_message_format": "ASCII 'yenc-body nonce' (15B) + uint32_be(segmentIndex) (4B) = 19B",
            "control_enc_key_format": "ASCII 'yenc-control key' (16B) = 16B",
            "control_tweak_message_format": "ASCII 'yenc-control tweak' (18B) + uint32_be(segmentIndex) (4B) + uint32_be(lineIndex) (4B) = 26B",
        },
        "body_nonce_vectors": body_vectors,
        "control_tweak_vectors": control_vectors,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Generated {len(body_vectors)} body nonce and {len(control_vectors)} control tweak vectors in {path.name}")


def generate_body_vectors(path: Path):
    """Generate VEC-03 XChaCha20-Poly1305 body encryption round-trip test vectors."""
    cases = [
        {
            "id": "body-vec-01-spec-example",
            "description": "Spec Section 10 example (16-byte binary payload)",
            "password": "test123",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 1,
            "plaintext": bytes.fromhex("48656C6C6F20576F726C642E747874FF"),
        },
        {
            "id": "body-vec-02-exact-block",
            "description": "64-byte payload (exact single ChaCha20 block boundary)",
            "password": "test123",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 1,
            "plaintext": bytes(i % 256 for i in range(64)),
        },
        {
            "id": "body-vec-03-multi-block",
            "description": "256-byte payload (4 ChaCha20 blocks)",
            "password": "test123",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 2,
            "plaintext": bytes((i * 7 + 13) % 256 for i in range(256)),
        },
        {
            "id": "body-vec-04-large-segment",
            "description": "4096-byte typical Usenet article segment chunk",
            "password": "P@ssw0rd with spaces & symbols!#$%",
            "salt_hex": "0102030405060708090a0b0c0d0e0f10",
            "segment_index": 1,
            "plaintext": bytes((i * 31 + 17) % 256 for i in range(4096)),
        },
        {
            "id": "body-vec-05-empty-payload",
            "description": "0-byte empty payload (edge case testing empty body)",
            "password": "test123",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 1,
            "plaintext": b"",
        },
        {
            "id": "body-vec-06-all-zeros",
            "description": "128 bytes of zero octets (0x00)",
            "password": "test123",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 3,
            "plaintext": bytes(128),
        },
        {
            "id": "body-vec-07-all-ones",
            "description": "128 bytes of 0xFF octets",
            "password": "test123",
            "salt_hex": "1a2b3c4d5e6f7890abcdef1234567890",
            "segment_index": 4,
            "plaintext": bytes([0xFF] * 128),
        },
        {
            "id": "body-vec-08-high-segment",
            "description": "128-byte payload with high segmentIndex=65536",
            "password": "Mötörhëad-Usenet-🔑-2026",
            "salt_hex": "fedcba98765432100123456789abcdef",
            "segment_index": 65536,
            "plaintext": bytes((i * 19 + 5) % 256 for i in range(128)),
        },
    ]

    vectors = []
    for tc in cases:
        salt = bytes.fromhex(tc["salt_hex"])
        key = derive_key(tc["password"], salt)
        nonce = derive_body_nonce(key, tc["segment_index"])
        ct, tag = body_encrypt(tc["plaintext"], key, nonce)

        # verify decrypt roundtrip immediately
        pt_roundtrip = body_decrypt(ct, tag, key, nonce)
        assert pt_roundtrip == tc["plaintext"]

        salt_hex_str = tc["salt_hex"].lower()
        tag_hex_str = tag.hex().lower()
        index_hex_str = f"{tc['segment_index']:08x}"
        expected_yenc_line = (
            f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex_str} index={index_hex_str} tag={tag_hex_str}"
        )
        assert len(expected_yenc_line) == 128

        vectors.append(
            {
                "id": tc["id"],
                "description": tc["description"],
                "password": tc["password"],
                "salt_hex": salt_hex_str,
                "segment_index": tc["segment_index"],
                "derived_key_hex": key.hex().lower(),
                "derived_nonce_hex": nonce.hex().lower(),
                "plaintext_length": len(tc["plaintext"]),
                "plaintext_hex": tc["plaintext"].hex().lower(),
                "expected_ciphertext_hex": ct.hex().lower(),
                "expected_index_hex": index_hex_str,
                "expected_tag_hex": tag_hex_str,
                "expected_yencryption_line": expected_yenc_line,
            }
        )

    fixture = {
        "schema_version": "1.0",
        "standard": "yEnc Body Encryption Standard v1.1",
        "requirement": "VEC-03",
        "cipher": "XChaCha20-Poly1305",
        "vectors": vectors,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Generated {len(vectors)} body encryption vectors in {path.name}")


def generate_control_line_vectors(path: Path):
    """Generate VEC-04 FF1 control-line encryption round-trip test vectors."""
    password = "test123"
    salt_hex = "4b376d5839704c32715238764e34775a"  # ASCII "K7mX9pL2qR8vN4wZ" (alphabet characters)
    salt_bytes = bytes.fromhex(salt_hex)
    master_key = derive_key(password, salt_bytes)

    # Line 1 vectors (with 20-byte prepended bootstrap expansion)
    line1_cases = [
        {
            "id": "control-vec-01-line-1-ybegin-single",
            "description": "Header line 1 single-part =ybegin with 20-byte prepended bootstrap expansion",
            "segment_index": 1,
            "line_index": 1,
            "plaintext_line": "=ybegin line=128 size=18 name=file.bin",
        },
        {
            "id": "control-vec-02-line-1-ybegin-multipart",
            "description": "Header line 1 multipart =ybegin with 20-byte prepended bootstrap expansion",
            "segment_index": 1,
            "line_index": 1,
            "plaintext_line": "=ybegin part=1 total=10 line=128 size=3500000 name=movie.mkv",
        },
    ]

    # Lines 2..N vectors (exact length preservation)
    subsequent_cases = [
        {
            "id": "control-vec-03-line-2-ypart",
            "description": "Header line 2 =ypart (exact length preservation)",
            "segment_index": 1,
            "line_index": 2,
            "plaintext_line": "=ypart begin=1 end=700000",
        },
        {
            "id": "control-vec-04-line-3-yencryption",
            "description": "Header line 3 =yencryption (exact length preservation)",
            "segment_index": 1,
            "line_index": 3,
            "plaintext_line": "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b",
        },
        {
            "id": "control-vec-05-line-4-yend-single",
            "description": "Footer line 4 =yend minimal (exact length preservation)",
            "segment_index": 1,
            "line_index": 4,
            "plaintext_line": "=yend size=18",
        },
        {
            "id": "control-vec-06-line-54-yend-multipart",
            "description": "Footer line 54 =yend multipart with pcrc32 (exact length preservation)",
            "segment_index": 1,
            "line_index": 54,
            "plaintext_line": "=yend size=700000 part=1 pcrc32=12345678",
        },
    ]

    vectors = []
    for tc in line1_cases:
        pt_bytes = tc["plaintext_line"].encode("ascii")
        enc_key, tweak = derive_control_keys(master_key, tc["segment_index"], tc["line_index"])
        ct_bytes = ff1_encrypt(enc_key, tweak, pt_bytes)
        # Line 1 prepends the 20-byte article bootstrap (16B salt + 4B uint32_be(segment_index))
        bootstrap_prefix = salt_bytes + uint32_be(tc["segment_index"])
        wire_bytes = bootstrap_prefix + ct_bytes

        # Verify decrypt: strip 20-byte bootstrap, decrypt ct
        extracted_salt, extracted_seg_idx, extracted_ct = extract_bootstrap_from_line1(wire_bytes)
        assert extracted_salt == salt_bytes
        assert extracted_seg_idx == tc["segment_index"]
        assert extracted_ct == ct_bytes
        restored_pt = ff1_decrypt(enc_key, tweak, extracted_ct)
        assert restored_pt == pt_bytes

        vectors.append(
            {
                "id": tc["id"],
                "description": tc["description"],
                "password": password,
                "salt_hex": salt_hex.lower(),
                "salt_ascii": salt_bytes.decode("ascii"),
                "segment_index": tc["segment_index"],
                "line_index": tc["line_index"],
                "is_line_1": True,
                "plaintext_line": tc["plaintext_line"],
                "plaintext_length": len(pt_bytes),
                "salt_length": 16,
                "bootstrap_length": 20,
                "expected_wire_length": len(wire_bytes),
                "derived_enc_key_hex": enc_key.hex().lower(),
                "derived_tweak_hex": tweak.hex().lower(),
                "expected_wire_hex": wire_bytes.hex().lower(),
            }
        )

    for tc in subsequent_cases:
        pt_bytes = tc["plaintext_line"].encode("ascii")
        enc_key, tweak = derive_control_keys(master_key, tc["segment_index"], tc["line_index"])
        wire_bytes = ff1_encrypt(enc_key, tweak, pt_bytes)

        # Verify decrypt
        restored_pt = ff1_decrypt(enc_key, tweak, wire_bytes)
        assert restored_pt == pt_bytes
        assert len(wire_bytes) == len(pt_bytes)

        vectors.append(
            {
                "id": tc["id"],
                "description": tc["description"],
                "password": password,
                "salt_hex": salt_hex.lower(),
                "segment_index": tc["segment_index"],
                "line_index": tc["line_index"],
                "is_line_1": False,
                "plaintext_line": tc["plaintext_line"],
                "plaintext_length": len(pt_bytes),
                "expected_wire_length": len(wire_bytes),
                "derived_enc_key_hex": enc_key.hex().lower(),
                "derived_tweak_hex": tweak.hex().lower(),
                "expected_wire_hex": wire_bytes.hex().lower(),
            }
        )

    # Full article vectors
    # 4-line minimal article: =ybegin (line 1), data line 1 (line 2), data line 2 (line 3), =yend (line 4)
    art4_lines = [
        "=ybegin line=128 size=18 name=file.bin",
        "DataLine1TestDataMustRemainUntouched1234567890",
        "DataLine2TestDataMustRemainUntouched1234567890",
        "=yend size=18",
    ]
    art4_wire = []
    for l_idx, line in enumerate(art4_lines, start=1):
        if line.startswith("=y"):
            enc_k, twk = derive_control_keys(master_key, 1, l_idx)
            ct_b = ff1_encrypt(enc_k, twk, line.encode("ascii"))
            if l_idx == 1:
                art4_wire.append((salt_bytes + uint32_be(1) + ct_b).hex().lower())
            else:
                art4_wire.append(ct_b.hex().lower())
        else:
            # Data line remains completely untouched
            art4_wire.append(line.encode("ascii").hex().lower())

    vectors.append(
        {
            "id": "control-vec-07-full-article-4-lines",
            "description": "Full 4-line article: line 1 bootstrap expansion, lines 2-3 data lines untouched, line 4 exact length",
            "password": password,
            "salt_hex": salt_hex.lower(),
            "segment_index": 1,
            "total_physical_lines": 4,
            "input_lines": art4_lines,
            "expected_wire_lines_hex": art4_wire,
        }
    )

    # 54-line article: =ybegin (1), =ypart (2), =yencryption (3), 50 data lines (4..53), =yend (54)
    art54_lines = [
        "=ybegin part=1 total=1 line=128 size=700000 name=data.bin",
        "=ypart begin=1 end=700000",
        "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b",
    ]
    for d in range(1, 51):
        art54_lines.append(f"TestDataLine{d:02d}ContentUntouchedByteForBytePadding1234567890")
    art54_lines.append("=yend size=700000 part=1 pcrc32=12345678")

    art54_wire = []
    for l_idx, line in enumerate(art54_lines, start=1):
        if line.startswith("=y"):
            enc_k, twk = derive_control_keys(master_key, 1, l_idx)
            ct_b = ff1_encrypt(enc_k, twk, line.encode("ascii"))
            if l_idx == 1:
                art54_wire.append((salt_bytes + uint32_be(1) + ct_b).hex().lower())
            else:
                art54_wire.append(ct_b.hex().lower())
        else:
            art54_wire.append(line.encode("ascii").hex().lower())

    vectors.append(
        {
            "id": "control-vec-08-full-article-54-lines",
            "description": "Full 54-line article: verifies physical line counting 1..54 across header, data, and footer",
            "password": password,
            "salt_hex": salt_hex.lower(),
            "segment_index": 1,
            "total_physical_lines": 54,
            "input_lines": art54_lines,
            "expected_wire_lines_hex": art54_wire,
        }
    )

    fixture = {
        "schema_version": "1.0",
        "standard": "yEnc Control Lines Encryption Standard v1.1",
        "requirement": "VEC-04",
        "cipher": "FF1",
        "radix": 253,
        "vectors": vectors,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Generated {len(vectors)} control-line encryption vectors in {path.name}")


def generate_malformed_input_vectors(path: Path):
    """Generate VEC-05 malformed-input rejection and zero-output test vectors."""
    password = "test123"
    salt_hex = "1a2b3c4d5e6f7890abcdef1234567890"
    salt = bytes.fromhex(salt_hex)
    key = derive_key(password, salt)
    nonce = derive_body_nonce(key, 1)
    pt = b"Hello World secret data 12345678"
    ct, tag = body_encrypt(pt, key, nonce)

    vectors = [
        # 1. Header Syntax Malformations
        {
            "id": "malformed-header-01-bad-cipher",
            "category": "header_syntax",
            "description": "Unsupported cipher algorithm (AES-256-GCM)",
            "input_line": f"=yencryption cipher=AES-256-GCM salt={salt_hex} index=00000001 tag={tag.hex()}",
            "expected_error": "UNSUPPORTED_CIPHER",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-02-chacha20-unauth",
            "category": "header_syntax",
            "description": "Unauthenticated cipher (ChaCha20 without Poly1305)",
            "input_line": f"=yencryption cipher=ChaCha20 salt={salt_hex} index=00000001 tag={tag.hex()}",
            "expected_error": "UNSUPPORTED_CIPHER",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-03-empty-cipher",
            "category": "header_syntax",
            "description": "Empty cipher parameter value",
            "input_line": f"=yencryption cipher= salt={salt_hex} index=00000001 tag={tag.hex()}",
            "expected_error": "INVALID_CIPHER",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-04-missing-salt",
            "category": "header_syntax",
            "description": "Missing salt parameter entirely",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 index=00000001 tag={tag.hex()}",
            "expected_error": "INVALID_TOKEN_COUNT",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-05-truncated-salt",
            "category": "header_syntax",
            "description": "Salt shorter than 32 hex characters (30 hex chars / 15 bytes)",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef12345678 index=00000001 tag={tag.hex()}",
            "expected_error": "INVALID_SALT_LENGTH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-06-extended-salt",
            "category": "header_syntax",
            "description": "Salt longer than 32 hex characters (34 hex chars / 17 bytes)",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890ff index=00000001 tag={tag.hex()}",
            "expected_error": "INVALID_SALT_LENGTH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-07-non-hex-salt",
            "category": "header_syntax",
            "description": "Salt containing non-hex characters ('g', 'z')",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef12345678gz index=00000001 tag={tag.hex()}",
            "expected_error": "INVALID_SALT_HEX",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-08-missing-tag",
            "category": "header_syntax",
            "description": "Missing tag parameter entirely",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000001",
            "expected_error": "INVALID_TOKEN_COUNT",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-09-truncated-tag",
            "category": "header_syntax",
            "description": "Tag shorter than 32 hex characters (30 hex chars / 15 bytes)",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000001 tag=0cd77ce245a654463f90b945b1d22d",
            "expected_error": "INVALID_TAG_LENGTH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-10-extended-tag",
            "category": "header_syntax",
            "description": "Tag longer than 32 hex characters (34 hex chars / 17 bytes)",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b00",
            "expected_error": "INVALID_TAG_LENGTH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-11-non-hex-tag",
            "category": "header_syntax",
            "description": "Tag containing non-hex characters ('x', 'y')",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000001 tag=0cd77ce245a654463f90b945b1d22dxy",
            "expected_error": "INVALID_TAG_HEX",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-12-missing-index",
            "category": "header_syntax",
            "description": "Four tokens omitting the mandatory index parameter",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} tag={tag.hex()}",
            "expected_error": "INVALID_TOKEN_COUNT",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-13-zero-index",
            "category": "header_syntax",
            "description": "Segment index 0 is strictly forbidden",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000000 tag={tag.hex()}",
            "expected_error": "ZERO_SEGMENT_INDEX",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-14-truncated-index",
            "category": "header_syntax",
            "description": "Index shorter than 8 hex characters (4 chars)",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=0001 tag={tag.hex()}",
            "expected_error": "INVALID_INDEX_LENGTH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-15-extended-index",
            "category": "header_syntax",
            "description": "Index longer than 8 hex characters (9 chars)",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=000000001 tag={tag.hex()}",
            "expected_error": "INVALID_INDEX_LENGTH",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-16-non-hex-index",
            "category": "header_syntax",
            "description": "Index containing non-hex characters ('g')",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=0000000g tag={tag.hex()}",
            "expected_error": "INVALID_INDEX_HEX",
            "zero_output_required": True,
        },
        {
            "id": "malformed-header-17-uppercase-index",
            "category": "header_syntax",
            "description": "Index containing uppercase hex digits",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=0000000F tag={tag.hex()}",
            "expected_error": "UPPERCASE_HEX",
            "zero_output_required": True,
        },
        # 2. Cryptographic Authentication Failures (Zero-Output Enforced)
        {
            "id": "auth-failure-01-tampered-ciphertext",
            "category": "auth_failure",
            "description": "Bit flip in body ciphertext must trigger authentication failure and zero output",
            "password": password,
            "salt_hex": salt_hex,
            "segment_index": 1,
            "tampered_ciphertext_hex": (bytes([ct[0] ^ 0x01]) + ct[1:]).hex().lower(),
            "tag_hex": tag.hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        {
            "id": "auth-failure-02-tampered-tag",
            "category": "auth_failure",
            "description": "Bit flip in authentication tag must trigger authentication failure and zero output",
            "password": password,
            "salt_hex": salt_hex,
            "segment_index": 1,
            "ciphertext_hex": ct.hex().lower(),
            "tampered_tag_hex": (bytes([tag[0] ^ 0x01]) + tag[1:]).hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        {
            "id": "auth-failure-03-wrong-password",
            "category": "auth_failure",
            "description": "Incorrect password must trigger authentication failure and zero output",
            "password": "wrong_password_999",
            "salt_hex": salt_hex,
            "segment_index": 1,
            "ciphertext_hex": ct.hex().lower(),
            "tag_hex": tag.hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        {
            "id": "auth-failure-04-mismatched-segment-index",
            "category": "auth_failure",
            "description": "Segment index mismatch (encrypted with index 1, decrypted with index 2)",
            "password": password,
            "salt_hex": salt_hex,
            "segment_index": 2,
            "ciphertext_hex": ct.hex().lower(),
            "tag_hex": tag.hex().lower(),
            "expected_error": "AUTHENTICATION_FAILURE",
            "zero_output_required": True,
        },
        # 3. Control Line Malformations
        {
            "id": "control-syntax-01-forbidden-lf-in-salt",
            "category": "control_syntax",
            "description": "Line 1 salt contains forbidden byte 0x0A (LF)",
            "tampered_salt_hex": "4b376d5839704c320a5238764e34775a",
            "expected_error": "INVALID_SALT_CHARACTER",
            "zero_output_required": True,
        },
        {
            "id": "control-syntax-02-forbidden-cr-in-salt",
            "category": "control_syntax",
            "description": "Line 1 salt contains forbidden byte 0x0D (CR)",
            "tampered_salt_hex": "4b376d5839704c320d5238764e34775a",
            "expected_error": "INVALID_SALT_CHARACTER",
            "zero_output_required": True,
        },
        {
            "id": "control-syntax-03-forbidden-nul-in-salt",
            "category": "control_syntax",
            "description": "Line 1 salt contains forbidden byte 0x00 (NUL)",
            "tampered_salt_hex": "4b376d5839704c32005238764e34775a",
            "expected_error": "INVALID_SALT_CHARACTER",
            "zero_output_required": True,
        },
        {
            "id": "control-syntax-04-line-too-short",
            "category": "control_syntax",
            "description": "Control line shorter than 2 characters",
            "line_hex": "3d",  # "=" (1 byte)
            "expected_error": "LINE_TOO_SHORT",
            "zero_output_required": True,
        },
        {
            "id": "control-syntax-05-line1-truncated",
            "category": "control_syntax",
            "description": "Line 1 length < 22 bytes (cannot contain 16B salt + 4B segmentIndex + 2B minlen)",
            "line1_hex": "4b376d5839704c32715238764e34775a000000013d",  # 21 bytes
            "expected_error": "LINE_TRUNCATED",
            "zero_output_required": True,
        },
        {
            "id": "control-syntax-06-zero-segment-index",
            "category": "control_syntax",
            "description": "Line 1 bootstrap contains prohibited zero segment index (0x00000000)",
            "line1_hex": "4b376d5839704c32715238764e34775a000000003d3d",  # 22 bytes, index=0
            "expected_error": "ZERO_SEGMENT_INDEX",
            "zero_output_required": True,
        },
        {
            "id": "control-syntax-07-wrong-password",
            "category": "control_syntax",
            "description": "Wrong password for control line decryption results in non-'=y' plaintext",
            "wrong_password": "wrong_control_password",
            "expected_error": "CONTROL_LINE_DECRYPT_FAILURE",
            "zero_output_required": True,
        },
    ]

    vectors.extend([
        {
            "id": "metadata-01-missing-provenance",
            "category": "metadata_validation",
            "description": "Encrypted article without the required transport provenance marker",
            "expected_error": "MISSING_ENCRYPTION_PROVENANCE",
            "expected_rejection_stage": "METADATA_VALIDATION",
            "provider_failover_permitted": False,
            "zero_output_required": True,
        },
        {
            "id": "metadata-02-false-provenance",
            "category": "metadata_validation",
            "description": "Transport provenance explicitly set to false",
            "expected_error": "INVALID_ENCRYPTION_PROVENANCE",
            "expected_rejection_stage": "METADATA_VALIDATION",
            "provider_failover_permitted": False,
            "zero_output_required": True,
        },
        {
            "id": "header-12-uppercase-hex",
            "category": "header_syntax",
            "description": "Uppercase hexadecimal salt is not canonical",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex.upper()} index=00000001 tag={tag.hex()}",
            "expected_error": "INVALID_SALT_HEX",
            "zero_output_required": True,
        },
        {
            "id": "header-13-extra-token",
            "category": "header_syntax",
            "description": "An extra parameter violates the five-token grammar",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000001 tag={tag.hex()} extra=value",
            "expected_error": "EXTRA_PARAMETER",
            "zero_output_required": True,
        },
        {
            "id": "header-14-reordered-token",
            "category": "header_syntax",
            "description": "Parameter order is canonical and mandatory",
            "input_line": f"=yencryption salt={salt_hex} cipher=XChaCha20-Poly1305 index=00000001 tag={tag.hex()}",
            "expected_error": "REORDERED_HEADER",
            "zero_output_required": True,
        },
        {
            "id": "placement-01-single-part-line-three",
            "category": "placement",
            "description": "Single-part encryption header must be on physical line 2",
            "line_index": 3,
            "multipart": False,
            "expected_error": "MISPLACED_ENCRYPTION_HEADER",
            "zero_output_required": True,
        },
        {
            "id": "placement-02-multipart-after-data",
            "category": "placement",
            "description": "Multipart encryption header must immediately follow =ypart",
            "line_index": 4,
            "multipart": True,
            "expected_error": "MISPLACED_ENCRYPTION_HEADER",
            "zero_output_required": True,
        },
        {
            "id": "salt-01-dual-salt-mismatch",
            "category": "salt_mismatch",
            "line1_salt_hex": "4b376d5839704c32715238764e34775a",
            "header_salt_hex": salt_hex,
            "line1_index": 1,
            "header_index": 1,
            "expected_error": "SALT_MISMATCH",
            "zero_output_required": True,
        },
        {
            "id": "dual-02-dual-index-mismatch",
            "category": "salt_mismatch",
            "line1_salt_hex": salt_hex,
            "header_salt_hex": salt_hex,
            "line1_index": 1,
            "header_index": 2,
            "expected_error": "DUAL_INDEX_MISMATCH",
            "zero_output_required": True,
        },
        {
            "id": "header-15-duplicate-token",
            "category": "header_syntax",
            "description": "Duplicate parameters are rejected",
            "input_line": f"=yencryption cipher=XChaCha20-Poly1305 salt={salt_hex} index=00000001 tag={tag.hex()} tag={tag.hex()}",
            "expected_error": "DUPLICATE_PARAMETER",
            "zero_output_required": True,
        },
        {
            "id": "metadata-03-missing-password",
            "category": "metadata_validation",
            "description": "Encrypted transport requires a password metadata value",
            "expected_error": "MISSING_PASSWORD",
            "expected_rejection_stage": "METADATA_VALIDATION",
            "provider_failover_permitted": False,
            "zero_output_required": True,
        },
    ])

    structural_categories = {"metadata_validation"}
    for vector in vectors:
        structural = vector["category"] in structural_categories
        vector["expected_rejection_stage"] = "METADATA_VALIDATION" if structural else "PROVIDER_FAILOVER"
        vector["provider_failover_permitted"] = not structural

    fixture = {
        "schema_version": "1.0",
        "standard": "yEnc Body & Control Lines Encryption Standards v1.1",
        "requirement": "VEC-05",
        "vectors": vectors,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Generated {len(vectors)} malformed input rejection vectors in {path.name}")


STRICT_SEGMENT_INDEX_RE = re.compile(r"^[1-9][0-9]*$")
MAX_UINT32 = 4294967295


def validate_segment_index_string(val_str: str) -> tuple[bool, str | None, int | None]:
    """Validate segmentIndex string per normative Section 8 requirements.

    Returns (is_valid, error_code, parsed_int).
    """
    if not val_str:
        return False, "INVALID_SEGMENT_INDEX_EMPTY", None

    if val_str == "0":
        return False, "INVALID_SEGMENT_INDEX_ZERO", None

    if val_str.startswith("+") or val_str.startswith("-"):
        return False, "INVALID_SEGMENT_INDEX_SIGN", None

    if val_str != val_str.strip() or any(c in val_str for c in (" ", "\t", "\n", "\r")):
        return False, "INVALID_SEGMENT_INDEX_WHITESPACE", None

    if len(val_str) > 1 and val_str.startswith("0") and val_str.isdigit():
        return False, "INVALID_SEGMENT_INDEX_LEADING_ZERO", None

    if not STRICT_SEGMENT_INDEX_RE.fullmatch(val_str):
        return False, "INVALID_SEGMENT_INDEX_NON_DIGIT", None

    val_int = int(val_str)
    if val_int > MAX_UINT32:
        return False, "INVALID_SEGMENT_INDEX_OVERFLOW", None

    return True, None, val_int


def make_nzb_xml(files_spec: list[dict], password: str | None = None, yenc_encrypted: bool = False, include_segment_index: bool = False) -> str:
    """Generate standard NZB 1.1 XML string for conformance test vectors."""
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN" "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">',
        '<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">',
    ]
    if password is not None:
        lines.append("  <head>")
        lines.append(f'    <meta type="password">{saxutils.escape(password)}</meta>')
        if yenc_encrypted:
            lines.append('    <meta type="yenc_encrypted">true</meta>')
        lines.append("  </head>")
    for f in files_spec:
        poster = saxutils.escape(f.get("poster", "poster@example.com"), {'"': '&quot;'})
        date = saxutils.escape(str(f.get("date", 1774300000)), {'"': '&quot;'})
        subject = saxutils.escape(f.get("subject", "file.bin"), {'"': '&quot;'})
        lines.append(f'  <file poster="{poster}" date="{date}" subject="{subject}">')
        lines.append("    <groups>")
        for g in f.get("groups", ["alt.binaries.test"]):
            lines.append(f"      <group>{saxutils.escape(g)}</group>")
        lines.append("    </groups>")
        lines.append("    <segments>")
        for s in f.get("segments", []):
            b = saxutils.escape(str(s.get("bytes", 750000)), {'"': '&quot;'})
            num = saxutils.escape(str(s.get("number", 1)), {'"': '&quot;'})
            mid = saxutils.escape(s.get("message_id", "art@example.com"))
            idx = s.get("segment_index")
            if (include_segment_index or s.get("emit_segment_index", False)) and idx is not None:
                idx_str = saxutils.escape(str(idx), {'"': '&quot;'})
                lines.append(f'      <segment bytes="{b}" number="{num}" segmentIndex="{idx_str}">{mid}</segment>')
            else:
                lines.append(f'      <segment bytes="{b}" number="{num}">{mid}</segment>')
        lines.append("    </segments>")
        lines.append("  </file>")
    lines.append("</nzb>")
    return "\n".join(lines)


def generate_nzb_segment_identity_vectors(path: Path):
    """Generate canonical clean NZB 1.1 fixtures for self-describing article identity (VEC-06)."""
    vectors = []

    # -------------------------------------------------------------------------
    # Category 1: valid_identity (10 vectors)
    # -------------------------------------------------------------------------
    vectors.append({
        "id": "nzb-valid-01-basic-sequential",
        "category": "valid_identity",
        "description": "Standard two-file release with sequential segmentIndex 1..3 across files",
        "expected_valid": True,
        "is_encrypted": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '[1/2] - "file1.bin" yEnc (1/2)',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 1, "message_id": "art-1@example.com"},
                    {"bytes": 750000, "number": 2, "segment_index": 2, "message_id": "art-2@example.com"},
                ],
            },
            {
                "subject": '[2/2] - "file2.bin" yEnc (1/1)',
                "segments": [
                    {"bytes": 500000, "number": 1, "segment_index": 3, "message_id": "art-3@example.com"},
                ],
            },
        ], password="test123", yenc_encrypted=True),
        "expected_segments": [
            {"message_id": "art-1@example.com", "part": 1, "bytes": 750000, "segment_index": 1},
            {"message_id": "art-2@example.com", "part": 2, "bytes": 750000, "segment_index": 2},
            {"message_id": "art-3@example.com", "part": 1, "bytes": 500000, "segment_index": 3},
        ],
    })

    vectors.append({
        "id": "nzb-valid-02-arbitrary-subject",
        "category": "valid_identity",
        "description": "Files with arbitrary descriptive subjects without [N/M] counters",
        "expected_valid": True,
        "is_encrypted": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": "Holiday Photos 2026 - Image Collection Part A",
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 1, "message_id": "art-arb-1@example.com"},
                ],
            },
            {
                "subject": "Holiday Photos 2026 - Image Collection Part B",
                "segments": [
                    {"bytes": 500000, "number": 1, "segment_index": 2, "message_id": "art-arb-2@example.com"},
                ],
            },
        ], password="test123", yenc_encrypted=True),
        "expected_segments": [
            {"message_id": "art-arb-1@example.com", "part": 1, "bytes": 750000, "segment_index": 1},
            {"message_id": "art-arb-2@example.com", "part": 1, "bytes": 500000, "segment_index": 2},
        ],
    })

    vectors.append({
        "id": "nzb-valid-03-obfuscated-subject",
        "category": "valid_identity",
        "description": "Files with random obfuscated hex hash subjects",
        "expected_valid": True,
        "is_encrypted": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": "a8f9c2d1e0b4a7d6e5f8",
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 1, "message_id": "art-obf-1@example.com"},
                ],
            },
            {
                "subject": "3b7c8d9e0f1a2b3c4d5e",
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 2, "message_id": "art-obf-2@example.com"},
                ],
            },
        ], password="test123", yenc_encrypted=True),
        "expected_segments": [
            {"message_id": "art-obf-1@example.com", "part": 1, "bytes": 750000, "segment_index": 1},
            {"message_id": "art-obf-2@example.com", "part": 1, "bytes": 750000, "segment_index": 2},
        ],
    })

    vectors.append({
        "id": "nzb-valid-04-misleading-counter",
        "category": "valid_identity",
        "description": "Subjects containing misleading [99/100] and (5/10) counters while segmentIndex is authoritative",
        "expected_valid": True,
        "is_encrypted": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '[99/100] - "misleading.bin" yEnc (5/10)',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 1, "message_id": "art-mis-1@example.com"},
                ],
            },
            {
                "subject": '[50/100] - "misleading.bin" yEnc (6/10)',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 2, "message_id": "art-mis-2@example.com"},
                ],
            },
        ], password="test123", yenc_encrypted=True),
        "expected_segments": [
            {"message_id": "art-mis-1@example.com", "part": 1, "bytes": 750000, "segment_index": 1},
            {"message_id": "art-mis-2@example.com", "part": 1, "bytes": 750000, "segment_index": 2},
        ],
    })

    vectors.append({
        "id": "nzb-valid-05-reordered-files",
        "category": "valid_identity",
        "description": "XML file elements appearing in reverse order with explicit indices preserved",
        "expected_valid": True,
        "is_encrypted": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '[2/2] - "file2.bin" yEnc (1/1)',
                "segments": [
                    {"bytes": 500000, "number": 1, "segment_index": 2, "message_id": "art-rf-2@example.com"},
                ],
            },
            {
                "subject": '[1/2] - "file1.bin" yEnc (1/1)',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 1, "message_id": "art-rf-1@example.com"},
                ],
            },
        ], password="test123", yenc_encrypted=True),
        "expected_segments": [
            {"message_id": "art-rf-2@example.com", "part": 1, "bytes": 500000, "segment_index": 2},
            {"message_id": "art-rf-1@example.com", "part": 1, "bytes": 750000, "segment_index": 1},
        ],
    })

    vectors.append({
        "id": "nzb-valid-06-reordered-segments",
        "category": "valid_identity",
        "description": "XML segment elements within file appearing out of order with explicit indices preserved",
        "expected_valid": True,
        "is_encrypted": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '[1/1] - "file.bin" yEnc (1/2)',
                "segments": [
                    {"bytes": 750000, "number": 2, "segment_index": 2, "message_id": "art-rs-2@example.com"},
                    {"bytes": 750000, "number": 1, "segment_index": 1, "message_id": "art-rs-1@example.com"},
                ],
            },
        ], password="test123", yenc_encrypted=True),
        "expected_segments": [
            {"message_id": "art-rs-2@example.com", "part": 2, "bytes": 750000, "segment_index": 2},
            {"message_id": "art-rs-1@example.com", "part": 1, "bytes": 750000, "segment_index": 1},
        ],
    })

    vectors.append({
        "id": "nzb-valid-07-boundary-lower-1",
        "category": "valid_identity",
        "description": "Single segment with lower boundary index 1",
        "expected_valid": True,
        "is_encrypted": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '"boundary_lower.bin"',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 1, "message_id": "art-b1@example.com"},
                ],
            },
        ], password="test123", yenc_encrypted=True),
        "expected_segments": [
            {"message_id": "art-b1@example.com", "part": 1, "bytes": 750000, "segment_index": 1},
        ],
    })

    vectors.append({
        "id": "nzb-valid-08-boundary-upper-max-uint32",
        "category": "valid_identity",
        "description": "Single segment with upper boundary index 4294967295 (max uint32)",
        "expected_valid": True,
        "is_encrypted": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '"boundary_upper.bin"',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 4294967295, "message_id": "art-bmax@example.com"},
                ],
            },
        ], password="test123", yenc_encrypted=True),
        "expected_segments": [
            {"message_id": "art-bmax@example.com", "part": 1, "bytes": 750000, "segment_index": 4294967295},
        ],
    })

    vectors.append({
        "id": "nzb-valid-09-sparse-indices",
        "category": "valid_identity",
        "description": "Segments with non-contiguous sparse indices (1, 5, 100)",
        "expected_valid": True,
        "is_encrypted": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '"sparse.bin"',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 1, "message_id": "art-sp-1@example.com"},
                    {"bytes": 750000, "number": 2, "segment_index": 5, "message_id": "art-sp-5@example.com"},
                    {"bytes": 750000, "number": 3, "segment_index": 100, "message_id": "art-sp-100@example.com"},
                ],
            },
        ], password="test123", yenc_encrypted=True),
        "expected_segments": [
            {"message_id": "art-sp-1@example.com", "part": 1, "bytes": 750000, "segment_index": 1},
            {"message_id": "art-sp-5@example.com", "part": 2, "bytes": 750000, "segment_index": 5},
            {"message_id": "art-sp-100@example.com", "part": 3, "bytes": 750000, "segment_index": 100},
        ],
    })

    vectors.append({
        "id": "nzb-valid-10-partial-nzb-subset",
        "category": "valid_identity",
        "description": "Partial NZB subset containing only file 2 (original segments 3 and 4) retaining original indices without renumbering",
        "expected_valid": True,
        "is_encrypted": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '[2/3] - "file2.bin" yEnc (1/2)',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 3, "message_id": "art-sub-3@example.com"},
                    {"bytes": 750000, "number": 2, "segment_index": 4, "message_id": "art-sub-4@example.com"},
                ],
            },
        ], password="test123", yenc_encrypted=True),
        "expected_segments": [
            {"message_id": "art-sub-3@example.com", "part": 1, "bytes": 750000, "segment_index": 3},
            {"message_id": "art-sub-4@example.com", "part": 2, "bytes": 750000, "segment_index": 4},
        ],
    })

    # -------------------------------------------------------------------------
    # Category 2: invalid_identity (19 vectors)
    # -------------------------------------------------------------------------
    invalid_cases = [
        ("nzb-invalid-01-zero-index", "0", "INVALID_SEGMENT_INDEX_ZERO", "segmentIndex='0' is strictly forbidden"),
        ("nzb-invalid-02-leading-zero-single", "01", "INVALID_SEGMENT_INDEX_LEADING_ZERO", "segmentIndex='01' has prohibited leading zero"),
        ("nzb-invalid-03-leading-zero-multi", "007", "INVALID_SEGMENT_INDEX_LEADING_ZERO", "segmentIndex='007' has prohibited leading zeroes"),
        ("nzb-invalid-04-plus-sign", "+1", "INVALID_SEGMENT_INDEX_SIGN", "segmentIndex='+1' has prohibited plus sign"),
        ("nzb-invalid-05-minus-sign", "-1", "INVALID_SEGMENT_INDEX_SIGN", "segmentIndex='-1' has prohibited minus sign"),
        ("nzb-invalid-06-leading-whitespace", " 1", "INVALID_SEGMENT_INDEX_WHITESPACE", "segmentIndex=' 1' has leading whitespace"),
        ("nzb-invalid-07-trailing-whitespace", "1 ", "INVALID_SEGMENT_INDEX_WHITESPACE", "segmentIndex='1 ' has trailing whitespace"),
        ("nzb-invalid-08-internal-whitespace", "1 2", "INVALID_SEGMENT_INDEX_WHITESPACE", "segmentIndex='1 2' has internal whitespace"),
        ("nzb-invalid-09-tab-character", "1\t", "INVALID_SEGMENT_INDEX_WHITESPACE", "segmentIndex='1\\t' contains tab whitespace"),
        ("nzb-invalid-10-newline-character", "1\n", "INVALID_SEGMENT_INDEX_WHITESPACE", "segmentIndex='1\\n' contains newline whitespace"),
        ("nzb-invalid-11-hex-prefix", "0x01", "INVALID_SEGMENT_INDEX_NON_DIGIT", "segmentIndex='0x01' has non-decimal hex characters"),
        ("nzb-invalid-12-float-decimal", "1.0", "INVALID_SEGMENT_INDEX_NON_DIGIT", "segmentIndex='1.0' has non-integer decimal point"),
        ("nzb-invalid-13-alpha-text", "one", "INVALID_SEGMENT_INDEX_NON_DIGIT", "segmentIndex='one' has alphabetic characters"),
        ("nzb-invalid-14-empty-string", "", "INVALID_SEGMENT_INDEX_EMPTY", "segmentIndex='' is an empty attribute value"),
        ("nzb-invalid-15-overflow-max-plus-1", "4294967296", "INVALID_SEGMENT_INDEX_OVERFLOW", "segmentIndex='4294967296' exceeds 32-bit unsigned integer max"),
        ("nzb-invalid-16-overflow-large", "18446744073709551615", "INVALID_SEGMENT_INDEX_OVERFLOW", "segmentIndex='18446744073709551615' exceeds 32-bit unsigned integer max"),
    ]

    for vec_id, val_str, err_code, desc in invalid_cases:
        vectors.append({
            "id": vec_id,
            "category": "legacy_attribute_ignored",
            "description": f"Legacy custom attribute ignored by clean NZB 1.1 parser: {desc}",
            "expected_valid": True,
            "is_encrypted": True,
            "legacy_segment_index": val_str,
            "legacy_expected_error": err_code,
            "nzb_xml": make_nzb_xml([
                {
                    "subject": '"invalid_file.bin"',
                    "segments": [
                        {"bytes": 750000, "number": 1, "segment_index": val_str, "message_id": f"art-{vec_id}@example.com"},
                    ],
                },
            ], password="test123", yenc_encrypted=True),
        })

    # Missing index on encrypted release
    vectors.append({
        "id": "nzb-invalid-17-missing-index-encrypted",
        "category": "invalid_identity",
        "description": "Password-protected release where a segment lacks segmentIndex attribute",
        "expected_valid": False,
        "expected_error": "MISSING_SEGMENT_INDEX",
        "expected_rejection_stage": "METADATA_VALIDATION",
        "zero_output_required": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '"missing_index.bin"',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": None, "message_id": "art-missing@example.com"},
                ],
            },
        ], password="test123"),
    })

    # Duplicate index across distinct Message-IDs
    vectors.append({
        "id": "nzb-invalid-18-duplicate-index",
        "category": "invalid_identity",
        "description": "Distinct Message-IDs in the same NZB declaring identical segmentIndex='1'",
        "expected_valid": False,
        "expected_error": "DUPLICATE_SEGMENT_INDEX",
        "expected_rejection_stage": "METADATA_VALIDATION",
        "zero_output_required": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '"duplicate_index.bin"',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 1, "message_id": "art-dup-1@example.com"},
                    {"bytes": 750000, "number": 2, "segment_index": 1, "message_id": "art-dup-2@example.com"},
                ],
            },
        ], password="test123"),
    })

    # Conflicting Message-ID mappings
    vectors.append({
        "id": "nzb-invalid-19-conflicting-message-id",
        "category": "invalid_identity",
        "description": "Same Message-ID declared multiple times with conflicting segmentIndex values",
        "expected_valid": False,
        "expected_error": "CONFLICTING_MESSAGE_ID_INDEX",
        "expected_rejection_stage": "METADATA_VALIDATION",
        "zero_output_required": True,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '"conflicting_mid_1.bin"',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 1, "message_id": "art-conflict@example.com"},
                ],
            },
            {
                "subject": '"conflicting_mid_2.bin"',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 2, "message_id": "art-conflict@example.com"},
                ],
            },
        ], password="test123"),
    })

    # -------------------------------------------------------------------------
    # Category 3: unencrypted_compatibility (2 vectors)
    # -------------------------------------------------------------------------
    vectors.append({
        "id": "nzb-compat-01-unencrypted-legacy",
        "category": "unencrypted_compatibility",
        "description": "Standard unencrypted NZB without password meta and without segmentIndex",
        "expected_valid": True,
        "is_encrypted": False,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '[1/1] - "legacy.bin" yEnc (1/1)',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": None, "message_id": "art-legacy@example.com"},
                ],
            },
        ], password=None),
        "expected_segments": [
            {"message_id": "art-legacy@example.com", "part": 1, "bytes": 750000, "segment_index": None},
        ],
    })

    vectors.append({
        "id": "nzb-compat-02-unencrypted-with-ignored-index",
        "category": "unencrypted_compatibility",
        "description": "Unencrypted NZB without password meta where segment carries segmentIndex; unencrypted parsers ignore unknown attribute",
        "expected_valid": True,
        "is_encrypted": False,
        "nzb_xml": make_nzb_xml([
            {
                "subject": '[1/1] - "compat.bin" yEnc (1/1)',
                "segments": [
                    {"bytes": 750000, "number": 1, "segment_index": 1, "message_id": "art-compat@example.com"},
                ],
            },
        ], password=None),
        "expected_segments": [
            {"message_id": "art-compat@example.com", "part": 1, "bytes": 750000, "segment_index": None},
        ],
    })

    # -------------------------------------------------------------------------
    # Category 4: index_tampering (2 vectors)
    # -------------------------------------------------------------------------
    # Vector 1: single-segment mismatch
    tamper1_pw = "test123"
    tamper1_salt_hex = "1a2b3c4d5e6f7890abcdef1234567890"
    tamper1_actual_idx = 1
    tamper1_tampered_idx = 2
    tamper1_pt = b"Sensitive plaintext data for index tampering test"
    tamper1_key = derive_key(tamper1_pw, bytes.fromhex(tamper1_salt_hex))
    tamper1_nonce = derive_body_nonce(tamper1_key, tamper1_actual_idx)
    tamper1_ct, tamper1_tag = body_encrypt(tamper1_pt, tamper1_key, tamper1_nonce)
    assert body_decrypt(tamper1_ct, tamper1_tag, tamper1_key, tamper1_nonce) == tamper1_pt

    vectors.append({
        "id": "nzb-tamper-01-index-mismatch-zero-output",
        "category": "index_tampering",
        "description": "Article encrypted with index 1; tampered NZB specifies index 2, failing Poly1305 verification with zero output",
        "expected_valid": True,
        "expected_error": "AUTHENTICATION_FAILURE",
        "expected_rejection_stage": "PROVIDER_FAILOVER",
        "zero_output_required": True,
        "password": tamper1_pw,
        "salt_hex": tamper1_salt_hex,
        "actual_segment_index": tamper1_actual_idx,
        "tampered_segment_index": tamper1_tampered_idx,
        "plaintext_hex": tamper1_pt.hex(),
        "ciphertext_hex": tamper1_ct.hex(),
        "tag_hex": tamper1_tag.hex(),
        "nzb_xml": make_nzb_xml([
            {
                "subject": '"tampered1.bin"',
                "segments": [
                    {"bytes": len(tamper1_ct), "number": 1, "segment_index": tamper1_tampered_idx, "message_id": "art-tamper-01@example.com"},
                ],
            },
        ], password=tamper1_pw, yenc_encrypted=True),
    })

    # Vector 2: index swap across two segments
    tamper2_pw = "test123"
    tamper2_salt_hex = "abcdef12345678901a2b3c4d5e6f7890"
    tamper2_key = derive_key(tamper2_pw, bytes.fromhex(tamper2_salt_hex))
    tamper2_pt1 = b"Payload for segment 1 in index swap security test"
    tamper2_pt2 = b"Payload for segment 2 in index swap security test"
    tamper2_nonce1 = derive_body_nonce(tamper2_key, 1)
    tamper2_nonce2 = derive_body_nonce(tamper2_key, 2)
    tamper2_ct1, tamper2_tag1 = body_encrypt(tamper2_pt1, tamper2_key, tamper2_nonce1)
    tamper2_ct2, tamper2_tag2 = body_encrypt(tamper2_pt2, tamper2_key, tamper2_nonce2)
    assert body_decrypt(tamper2_ct1, tamper2_tag1, tamper2_key, tamper2_nonce1) == tamper2_pt1
    assert body_decrypt(tamper2_ct2, tamper2_tag2, tamper2_key, tamper2_nonce2) == tamper2_pt2

    vectors.append({
        "id": "nzb-tamper-02-index-swap-zero-output",
        "category": "index_tampering",
        "description": "Two articles with swapped segmentIndex values in NZB; both fail authentication with zero output",
        "expected_valid": True,
        "expected_error": "AUTHENTICATION_FAILURE",
        "expected_rejection_stage": "PROVIDER_FAILOVER",
        "zero_output_required": True,
        "password": tamper2_pw,
        "salt_hex": tamper2_salt_hex,
        "tampered_segments": [
            {
                "message_id": "art-tamper-02a@example.com",
                "actual_segment_index": 1,
                "tampered_segment_index": 2,
                "plaintext_hex": tamper2_pt1.hex(),
                "ciphertext_hex": tamper2_ct1.hex(),
                "tag_hex": tamper2_tag1.hex(),
            },
            {
                "message_id": "art-tamper-02b@example.com",
                "actual_segment_index": 2,
                "tampered_segment_index": 1,
                "plaintext_hex": tamper2_pt2.hex(),
                "ciphertext_hex": tamper2_ct2.hex(),
                "tag_hex": tamper2_tag2.hex(),
            },
        ],
        "nzb_xml": make_nzb_xml([
            {
                "subject": '"swapped.bin"',
                "segments": [
                    {"bytes": len(tamper2_ct1), "number": 1, "segment_index": 2, "message_id": "art-tamper-02a@example.com"},
                    {"bytes": len(tamper2_ct2), "number": 2, "segment_index": 1, "message_id": "art-tamper-02b@example.com"},
                ],
            },
        ], password=tamper2_pw, yenc_encrypted=True),
    })

    fixture = {
        "schema_version": "1.0",
        "standard": "yEnc Body & Control Lines Encryption Standards v1.1",
        "requirement": "VEC-06",
        "vectors": vectors,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Generated {len(vectors)} NZB segment identity vectors in {path.name}")


def generate_manifest(output_dir: Path):
    """Generate manifest.json with SHA-256 hashes and vector counts."""
    files_meta = {
        "argon2id.json": {
            "description": "RFC 9106 Argon2id key derivation test vectors (VEC-01)",
            "requirement": "VEC-01",
        },
        "nonce_tweak.json": {
            "description": "HMAC-SHA256 nonce and tweak derivation test vectors (VEC-02)",
            "requirement": "VEC-02",
        },
        "body_encryption.json": {
            "description": "RFC 8439 Extended XChaCha20-Poly1305 body encryption round-trip vectors (VEC-03)",
            "requirement": "VEC-03",
        },
        "control_line_encryption.json": {
            "description": "NIST SP 800-38G FF1 control-line encryption round-trip vectors (VEC-04)",
            "requirement": "VEC-04",
        },
        "malformed_inputs.json": {
            "description": "Malformed syntax, invalid parameters, and auth failure rejection vectors (VEC-05)",
            "requirement": "VEC-05",
        },
        "nzb_segment_identity.json": {
            "description": "Clean NZB 1.1 self-describing article identity and compatibility vectors (VEC-06)",
            "requirement": "VEC-06",
        },
    }

    files_dict = {}
    for filename, meta in files_meta.items():
        file_path = output_dir / filename
        if not file_path.is_file():
            raise FileNotFoundError(f"Fixture file missing for manifest: {file_path}")
        raw_bytes = file_path.read_bytes()
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        data = json.loads(raw_bytes.decode("utf-8"))

        if "vectors" in data:
            v_count = len(data["vectors"])
        elif "body_nonce_vectors" in data and "control_tweak_vectors" in data:
            v_count = len(data["body_nonce_vectors"]) + len(data["control_tweak_vectors"])
        else:
            v_count = 0

        files_dict[filename] = {
            "sha256": sha256_hash,
            "vector_count": v_count,
            "description": meta["description"],
            "requirement": meta["requirement"],
        }

    manifest = {
        "schema_version": "1.0",
        "standard_version": "1.1",
        "generated_at": "2026-10-01T04:55:00Z",
        "description": "Deterministic test vectors for yEnc Body & Control Lines Encryption Standards v1.1",
        "files": files_dict,
    }

    manifest_path = output_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Generated manifest.json in {output_dir}")


def main():
    repo_root = Path(__file__).resolve().parent.parent
    output_dir = repo_root / "test-vectors"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating deterministic conformance test vectors into: {output_dir}")
    generate_argon2id_vectors(output_dir / "argon2id.json")
    generate_nonce_tweak_vectors(output_dir / "nonce_tweak.json")
    generate_body_vectors(output_dir / "body_encryption.json")
    generate_control_line_vectors(output_dir / "control_line_encryption.json")
    generate_malformed_input_vectors(output_dir / "malformed_inputs.json")
    generate_nzb_segment_identity_vectors(output_dir / "nzb_segment_identity.json")
    generate_manifest(output_dir)
    print("All conformance fixtures and manifest successfully generated.")


if __name__ == "__main__":
    main()
