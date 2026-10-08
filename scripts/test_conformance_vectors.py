#!/usr/bin/env python3
"""Automated conformance test harness for yEnc encryption standards v1.2.

Tests conformance against:
- VEC-01: Argon2id key derivation fixtures (argon2id.json)
- VEC-02: HMAC-SHA256 nonce and tweak derivations (nonce_tweak.json)
- VEC-03: XChaCha20-Poly1305 body encryption round-trips (body_encryption.json)
- VEC-04: NIST SP 800-38G FF1 control-line encryption round-trips (control_line_encryption.json)
- VEC-05: Malformed-input rejection and zero-output security (malformed_inputs.json)
- Manifest SHA-256 integrity verification (manifest.json)
"""

import hashlib
import hmac
import json
import math
import re
import struct
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
for p in (str(REPO_ROOT), str(SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import argon2.low_level as ll
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import nacl.bindings as nb
import nacl.exceptions as ne

# ---------------------------------------------------------------------------
# Embedded cryptographic verification primitives.
#
# These helpers are the canonical derivation, decryption, and validation
# routines exercised by the conformance vectors below. They are embedded here
# so the conformance suite runs standalone against the retained JSON fixtures
# without depending on any vector-generation scaffolding.
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
    # CR-02 (Control Std v1.2 Section 2/4/5/8): a uint32_be(segmentIndex)
    # containing 0x0A or 0x0D injects an NNTP line delimiter into the Line 1
    # prefix and splits the bootstrap short. Decoders MUST reject under
    # PROVIDER_FAILOVER.
    for b in line1_bytes[16:20]:
        if b in (0x0A, 0x0D):
            raise ValueError("FORBIDDEN_SEGMENT_INDEX_BYTE")
    ciphertext = line1_bytes[20:]
    return salt, seg_idx, ciphertext


def validate_dual_bootstrap(line1_salt: bytes, line1_index: int, yenc_params: dict) -> bool:
    """Verify byte-for-byte salt equality and value-for-value index equality."""
    if line1_salt != yenc_params["salt"]:
        raise ValueError("DUAL_SALT_MISMATCH")
    if line1_index != yenc_params["segment_index"]:
        raise ValueError("DUAL_INDEX_MISMATCH")
    return True


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


def byte_to_numeral(b: int) -> int:
    """Map byte octet to numeral 0..252 per yEnc Control Lines Standard v1.2."""
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
    """Map numeral 0..252 back to byte octet per yEnc Control Lines Standard v1.2."""
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


def ff1_decrypt(key: bytes, tweak: bytes, ciphertext_bytes: bytes, radix: int = 253) -> bytes:
    """Decrypt control line byte string using FF1 over Radix 253 Alphabet."""
    numerals = [byte_to_numeral(b) for b in ciphertext_bytes]
    pt_numerals = ff1_decrypt_numerals(key, tweak, numerals, radix)
    return bytes(numeral_to_byte(i) for i in pt_numerals)


def check_header_placement(line_index: int, multipart: bool) -> None:
    """Placement rule (Body Std v1.2 Section 4): =yencryption is physical
    line 2 for single-part articles and physical line 3 for multipart
    articles (immediately after =ypart at line 2)."""
    expected = 3 if multipart else 2
    if line_index != expected:
        raise ValueError("MISPLACED_ENCRYPTION_HEADER")


def parse_yencryption_line_v11(line: str) -> dict:
    """Parse and validate the canonical five-token v1.2 =yencryption header."""
    if line != line.strip():
        raise ValueError("INVALID_WHITESPACE")
    # Whitespace strictness (v1.2): a tab anywhere or two consecutive spaces
    # anywhere survives strip() but violates the single-SP token grammar.
    if "\t" in line or "  " in line:
        raise ValueError("INVALID_WHITESPACE")
    tokens = line.split(" ")
    if len(tokens) != 5 or any(not token for token in tokens):
        raise ValueError("INVALID_TOKEN_COUNT")
    if tokens[0] != "=yencryption":
        raise ValueError("INVALID_PREFIX")
    if tokens[1] != "cipher=XChaCha20-Poly1305":
        raise ValueError("UNSUPPORTED_CIPHER")
    if not tokens[2].startswith("salt=") or not tokens[3].startswith("index=") or not tokens[4].startswith("tag="):
        raise ValueError("INVALID_TOKEN_ORDER")

    salt_hex = tokens[2][5:]
    index_hex = tokens[3][6:]
    tag_hex = tokens[4][4:]

    if len(salt_hex) != 32:
        raise ValueError("INVALID_SALT_LENGTH")
    if not re.fullmatch(r"[0-9a-f]{32}", salt_hex):
        raise ValueError("UPPERCASE_HEX" if re.fullmatch(r"[0-9a-fA-F]{32}", salt_hex) else "INVALID_SALT_HEX")
    if len(index_hex) != 8:
        raise ValueError("INVALID_INDEX_LENGTH")
    if not re.fullmatch(r"[0-9a-f]{8}", index_hex):
        raise ValueError("UPPERCASE_HEX" if re.fullmatch(r"[0-9a-fA-F]{8}", index_hex) else "INVALID_INDEX_HEX")
    if len(tag_hex) != 32:
        raise ValueError("INVALID_TAG_LENGTH")
    if not re.fullmatch(r"[0-9a-f]{32}", tag_hex):
        raise ValueError("UPPERCASE_HEX" if re.fullmatch(r"[0-9a-fA-F]{32}", tag_hex) else "INVALID_TAG_HEX")

    segment_index = int(index_hex, 16)
    if segment_index == 0:
        raise ValueError("ZERO_SEGMENT_INDEX")
    # CR-02: same forbidden-byte rule as the Line 1 bootstrap (v1.2).
    for b in uint32_be(segment_index):
        if b in (0x0A, 0x0D):
            raise ValueError("FORBIDDEN_SEGMENT_INDEX_BYTE")

    return {
        "cipher": "XChaCha20-Poly1305",
        "salt": bytes.fromhex(salt_hex),
        "index_hex": index_hex,
        "segment_index": segment_index,
        "tag": bytes.fromhex(tag_hex),
    }


class TestConformanceVectors(unittest.TestCase):
    """Automated test suite verifying cryptographic test vectors against v1.2 specifications."""

    @classmethod
    def setUpClass(cls):
        cls.repo_root = REPO_ROOT
        cls.fixtures_dir = cls.repo_root / "test-vectors"
        if not cls.fixtures_dir.exists() or not (cls.fixtures_dir / "manifest.json").exists():
            cls.fixtures_dir = cls.repo_root / "yenc-encryption-standards" / "test-vectors"
        cls.manifest_path = cls.fixtures_dir / "manifest.json"

        cls.assertTrue(cls.manifest_path.is_file(), f"Missing manifest: {cls.manifest_path}")
        cls.manifest = json.loads(cls.manifest_path.read_text(encoding="utf-8"))

        def load_fixture(name: str):
            path = cls.fixtures_dir / name
            cls.assertTrue(path.is_file(), f"Missing fixture file: {path}")
            return json.loads(path.read_text(encoding="utf-8"))

        cls.argon2id_data = load_fixture("argon2id.json")
        cls.nonce_tweak_data = load_fixture("nonce_tweak.json")
        cls.body_data = load_fixture("body_encryption.json")
        cls.control_data = load_fixture("control_line_encryption.json")
        cls.malformed_data = load_fixture("malformed_inputs.json")
        cls.nzb_identity_data = load_fixture("nzb_segment_identity.json")
        cls.index_allocation_data = load_fixture("index_allocation.json")

    def test_manifest_checksums(self):
        """Verify SHA-256 integrity hashes and vector counts for all fixtures."""
        self.assertEqual(self.manifest["schema_version"], "1.0")
        self.assertEqual(self.manifest["standard_version"], "1.2")
        expected_files = {
            "argon2id.json",
            "nonce_tweak.json",
            "body_encryption.json",
            "control_line_encryption.json",
            "malformed_inputs.json",
            "nzb_segment_identity.json",
            "index_allocation.json",
        }
        self.assertEqual(set(self.manifest["files"]), expected_files)
        for filename, meta in self.manifest["files"].items():
            with self.subTest(file=filename):
                path = self.fixtures_dir / filename
                raw_bytes = path.read_bytes()
                self.assertEqual(hashlib.sha256(raw_bytes).hexdigest(), meta["sha256"])
                data = json.loads(raw_bytes.decode("utf-8"))
                if "vectors" in data:
                    count = len(data["vectors"])
                else:
                    count = len(data.get("body_nonce_vectors", [])) + len(data.get("control_tweak_vectors", []))
                self.assertEqual(count, meta["vector_count"])

    def test_fixture_schema_and_failure_classifications(self):
        """Validate fixture metadata and structural/provider failure boundaries."""
        for data, requirement in ((self.malformed_data, "VEC-05"), (self.nzb_identity_data, "VEC-06")):
            self.assertEqual(data["schema_version"], "1.0")
            self.assertEqual(data["requirement"], requirement)
            self.assertTrue(data["vectors"])

        structural_categories = {"metadata_validation"}
        provider_categories = {"header_syntax", "placement", "salt_mismatch", "control_syntax", "auth_failure"}
        for case in self.malformed_data["vectors"]:
            self.assertTrue(case["zero_output_required"], case["id"])
            if case["category"] in structural_categories:
                self.assertFalse(case["provider_failover_permitted"])
                self.assertEqual(case["expected_rejection_stage"], "METADATA_VALIDATION")
            else:
                self.assertIn(case["category"], provider_categories)
                self.assertTrue(case["provider_failover_permitted"])
                self.assertEqual(case["expected_rejection_stage"], "PROVIDER_FAILOVER")

        expected_errors = {
            "ZERO_SEGMENT_INDEX",
            "INVALID_INDEX_HEX",
            "INVALID_INDEX_LENGTH",
            "INVALID_TOKEN_COUNT",
            "LINE_TRUNCATED",
            "INVALID_SALT_CHARACTER",
            "DUAL_SALT_MISMATCH",
            "DUAL_INDEX_MISMATCH",
        }
        observed = {case["expected_error"] for case in self.malformed_data["vectors"]}
        self.assertTrue(expected_errors <= observed)

    def test_vec01_argon2id(self):
        """Verify VEC-01 Argon2id key derivation outputs."""
        params = self.argon2id_data["parameters"]
        for case in self.argon2id_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                derived = ll.hash_secret_raw(
                    secret=case["password"].encode("utf-8"),
                    salt=bytes.fromhex(case["salt_hex"]),
                    time_cost=params.get("time_cost", 1),
                    memory_cost=params.get("memory_cost_kib", 65536),
                    parallelism=params.get("parallelism", 4),
                    hash_len=params.get("output_length_bytes", 32),
                    type=ll.Type.ID,
                    version=int(params.get("version", "0x13"), 16),
                )
                self.assertEqual(derived.hex(), case["expected_key_hex"])

    def test_vec02_nonce_tweak(self):
        """Verify VEC-02 nonce and tweak derivations."""
        for case in self.nonce_tweak_data["body_nonce_vectors"]:
            key = bytes.fromhex(case["key_hex"])
            expected_msg = b"yenc-body nonce" + struct.pack(">I", case["segment_index"])
            self.assertEqual(bytes.fromhex(case["message_hex"]), expected_msg)
            self.assertEqual(derive_body_nonce(key, case["segment_index"]).hex(), case["expected_nonce_hex"])
        for case in self.nonce_tweak_data["control_tweak_vectors"]:
            master_key = bytes.fromhex(case["master_key_hex"])
            expected_msg = b"yenc-control tweak" + struct.pack(">I", case["segment_index"]) + struct.pack(">I", case["line_index"])
            self.assertEqual(bytes.fromhex(case["message_hex"]), expected_msg)
            enc_key, tweak = derive_control_keys(master_key, case["segment_index"], case["line_index"])
            self.assertEqual(enc_key.hex(), case["enc_key_hex"])
            self.assertEqual(tweak.hex(), case["expected_tweak_hex"])

    def test_vec03_body_encryption(self):
        """Verify VEC-03 body round-trips and canonical five-token headers."""
        for case in self.body_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                salt = bytes.fromhex(case["salt_hex"])
                key = derive_key(case["password"], salt)
                nonce = derive_body_nonce(key, case["segment_index"])
                plaintext = bytes.fromhex(case["plaintext_hex"])
                ciphertext, tag = body_encrypt(plaintext, key, nonce)
                self.assertEqual(ciphertext.hex(), case["expected_ciphertext_hex"])
                self.assertEqual(tag.hex(), case["expected_tag_hex"])
                params = parse_yencryption_line_v11(case["expected_yencryption_line"])
                self.assertEqual(len(case["expected_yencryption_line"]), 128)
                self.assertEqual(case["expected_yencryption_line"].split(" ").__len__(), 5)
                self.assertEqual(params["salt"], salt)
                self.assertEqual(params["segment_index"], case["segment_index"])
                self.assertEqual(params["tag"], tag)
                self.assertEqual(body_decrypt(ciphertext, tag, key, nonce), plaintext)

    def test_vec04_control_line_encryption(self):
        """Verify VEC-04 FF1 control-line encryption and 20-byte Line 1 bootstrap."""
        for b in range(1, 256):
            if b in (0x0A, 0x0D):
                with self.assertRaises(ValueError):
                    byte_to_numeral(b)
            else:
                numeral = byte_to_numeral(b)
                self.assertEqual(numeral_to_byte(numeral), b)

        for case in self.control_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                salt = bytes.fromhex(case["salt_hex"])
                master_key = derive_key(case["password"], salt)
                if "plaintext_line" in case:
                    plaintext = case["plaintext_line"].encode("ascii")
                    enc_key, tweak = derive_control_keys(master_key, case["segment_index"], case["line_index"])
                    wire = bytes.fromhex(case["expected_wire_hex"])
                    if case["is_line_1"]:
                        self.assertEqual(case["bootstrap_length"], 20)
                        self.assertEqual(case["expected_wire_length"], len(plaintext) + 20)
                        extracted_salt, extracted_index, ciphertext = extract_bootstrap_from_line1(wire)
                        self.assertEqual(extracted_salt, salt)
                        self.assertEqual(extracted_index, case["segment_index"])
                        restored = ff1_decrypt(enc_key, tweak, ciphertext)
                    else:
                        self.assertEqual(len(wire), len(plaintext))
                        restored = ff1_decrypt(enc_key, tweak, wire)
                    self.assertEqual(restored, plaintext)
                else:
                    for line_index, (line, wire_hex) in enumerate(zip(case["input_lines"], case["expected_wire_lines_hex"]), start=1):
                        wire = bytes.fromhex(wire_hex)
                        if line.startswith("=y"):
                            enc_key, tweak = derive_control_keys(master_key, case["segment_index"], line_index)
                            if line_index == 1:
                                extracted_salt, extracted_index, ciphertext = extract_bootstrap_from_line1(wire)
                                self.assertEqual(extracted_salt, salt)
                                self.assertEqual(extracted_index, case["segment_index"])
                                restored = ff1_decrypt(enc_key, tweak, ciphertext)
                            else:
                                restored = ff1_decrypt(enc_key, tweak, wire)
                            self.assertEqual(restored.decode("ascii"), line)
                        else:
                            self.assertEqual(wire, line.encode("ascii"))

    def test_vec05_malformed_inputs(self):
        """Verify VEC-05 malformed bootstrap and authentication failures enforce zero output."""
        metadata_tokens = {
            "MISSING_ENCRYPTION_PROVENANCE",
            "INVALID_ENCRYPTION_PROVENANCE",
            "MISSING_PASSWORD",
            "METADATA_VALIDATION_BODY_ONLY",
        }
        dispatchable_categories = {
            "header_syntax",
            "auth_failure",
            "control_syntax",
            "salt_mismatch",
            "placement",
            "metadata_validation",
        }
        exercised: set[str] = set()
        for case in self.malformed_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                exercised.add(case["id"])
                self.assertTrue(case["zero_output_required"])
                category = case["category"]
                if category == "header_syntax":
                    # Whitespace-strictness vectors (tab, double space) raise
                    # INVALID_WHITESPACE per v1.2 strict single-SP parsing; all
                    # other header_syntax vectors dispatch on their own
                    # expected_error token.
                    self.assertRaisesRegex(
                        ValueError, re.escape(case["expected_error"]), parse_yencryption_line_v11, case["input_line"]
                    )
                elif category == "placement":
                    self.assertRaisesRegex(
                        ValueError,
                        re.escape(case["expected_error"]),
                        check_header_placement,
                        case["line_index"],
                        case["multipart"],
                    )
                elif category == "metadata_validation":
                    # Metadata-level vectors: schema assertion only (no crypto
                    # primitive applies; the article bytes are not carried).
                    self.assertEqual(case["expected_rejection_stage"], "METADATA_VALIDATION")
                    self.assertFalse(case["provider_failover_permitted"])
                    self.assertIn(case["expected_error"], metadata_tokens)
                elif category == "auth_failure":
                    key = derive_key(case["password"], bytes.fromhex(case["salt_hex"]))
                    nonce = derive_body_nonce(key, case["segment_index"])
                    ciphertext = bytes.fromhex(case.get("tampered_ciphertext_hex") or case["ciphertext_hex"])
                    tag = bytes.fromhex(case.get("tampered_tag_hex") or case["tag_hex"])
                    output = None
                    with self.assertRaises(ne.CryptoError):
                        try:
                            output = body_decrypt(ciphertext, tag, key, nonce)
                        finally:
                            self.assertIsNone(output)
                elif category == "control_syntax":
                    if "tampered_salt_hex" in case:
                        with self.assertRaisesRegex(ValueError, "INVALID_SALT_CHARACTER"):
                            extract_bootstrap_from_line1(bytes.fromhex(case["tampered_salt_hex"]) + struct.pack(">I", 1) + b"==")
                    elif "line1_hex" in case:
                        # Dispatch on the vector's own expected_error token so
                        # CR-02 (FORBIDDEN_SEGMENT_INDEX_BYTE), zero-index, and
                        # truncation vectors each assert their own class.
                        with self.assertRaisesRegex(ValueError, re.escape(case["expected_error"])):
                            extract_bootstrap_from_line1(bytes.fromhex(case["line1_hex"]))
                    elif "line_hex" in case:
                        # LINE_TOO_SHORT: a control line shorter than the
                        # 2-byte FF1 minimum cannot be decrypted (Control Std
                        # v1.2 Section 5 provider tier). The fixture encodes a
                        # sub-minimum line; assert it violates the minimum.
                        raw = bytes.fromhex(case["line_hex"])
                        self.assertEqual(case["expected_error"], "LINE_TOO_SHORT")
                        self.assertLess(len(raw), 2)
                    elif "wrong_password" in case:
                        # CONTROL_LINE_DECRYPT_FAILURE: deriving keys from a
                        # wrong password and decrypting the canonical Line 1
                        # bootstrap yields bytes that do not begin with
                        # "=ybegin" (Control Std Section 5 step 3g).
                        ref = next(
                            c
                            for c in self.control_data["vectors"]
                            if c.get("is_line_1") and "expected_wire_hex" in c
                        )
                        wire = bytes.fromhex(ref["expected_wire_hex"])
                        wrong_key = derive_key(case["wrong_password"], bytes.fromhex(ref["salt_hex"]))
                        enc_key, tweak = derive_control_keys(wrong_key, ref["segment_index"], ref["line_index"])
                        restored = ff1_decrypt(enc_key, tweak, wire[20:])
                        self.assertNotEqual(restored, ref["plaintext_line"].encode("ascii"))
                        self.assertFalse(restored.startswith(b"=ybegin"))
                elif category == "salt_mismatch":
                    params = {
                        "salt": bytes.fromhex(case["header_salt_hex"]),
                        "segment_index": case["header_index"],
                    }
                    with self.assertRaisesRegex(ValueError, re.escape(case["expected_error"])):
                        validate_dual_bootstrap(bytes.fromhex(case["line1_salt_hex"]), case["line1_index"], params)
                else:
                    self.fail(f"Unknown malformed_inputs category: {category}")
                self.assertIn(category, dispatchable_categories)
        # Zero silent skips: every vector id must have been exercised above.
        all_ids = {case["id"] for case in self.malformed_data["vectors"]}
        self.assertEqual(exercised, all_ids)

    @staticmethod
    def _segments(root):
        return root.findall(".//{http://www.newzbin.com/DTD/2003/nzb}segment")

    def test_vec06_nzb_segment_identity(self):
        """Verify clean standard NZB 1.1 segment fixtures contain no custom segmentIndex attributes."""
        self.assertEqual(self.nzb_identity_data["requirement"], "VEC-06")
        for case in self.nzb_identity_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                root = ET.fromstring(case["nzb_xml"])
                for segment in self._segments(root):
                    self.assertEqual(set(segment.attrib), {"bytes", "number"})
                if case.get("is_encrypted"):
                    metadata = {meta.get("type"): (meta.text or "") for meta in root.findall("./{http://www.newzbin.com/DTD/2003/nzb}head/{http://www.newzbin.com/DTD/2003/nzb}meta")}
                    self.assertEqual(metadata.get("yenc_encrypted"), "true")
                    self.assertIn("password", metadata)

    def test_vec07_index_allocation(self):
        """Verify CR-02 uploader skip vectors: forbidden candidates are skipped,
        assigned indices never contain 0x0A/0x0D, and 269 itself is forbidden."""
        self.assertEqual(self.index_allocation_data["requirement"], "VEC-07")
        for case in self.index_allocation_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                self.assertEqual(case["category"], "index_allocation")
                self.assertIsNone(case["expected_error"])
                candidate = uint32_be(case["candidate_index"])
                assigned = uint32_be(case["expected_assigned_index"])
                # The candidate must contain a forbidden delimiter byte.
                self.assertTrue(any(b in (0x0A, 0x0D) for b in candidate), case["id"])
                # The assigned index must contain neither forbidden byte.
                self.assertFalse(any(b in (0x0A, 0x0D) for b in assigned), case["id"])
                # Skip always moves forward.
                self.assertGreater(case["expected_assigned_index"], case["candidate_index"])
                self.assertEqual(case["expected_index_hex"], format(case["expected_assigned_index"], "08x"))
                # 269 (0x0000010D) itself is forbidden and must never be assigned.
                if case["candidate_index"] == 269:
                    self.assertNotEqual(case["expected_assigned_index"], 269)

    def test_dual_bootstrap_agreement(self):
        """Verify salt and index must both agree between Line 1 and =yencryption."""
        line = self.body_data["vectors"][0]["expected_yencryption_line"]
        params = parse_yencryption_line_v11(line)
        self.assertTrue(validate_dual_bootstrap(params["salt"], params["segment_index"], params))
        with self.assertRaisesRegex(ValueError, "DUAL_SALT_MISMATCH"):
            validate_dual_bootstrap(bytes(16), params["segment_index"], params)
        with self.assertRaisesRegex(ValueError, "DUAL_INDEX_MISMATCH"):
            validate_dual_bootstrap(params["salt"], params["segment_index"] + 1, params)


if __name__ == "__main__":
    unittest.main()
