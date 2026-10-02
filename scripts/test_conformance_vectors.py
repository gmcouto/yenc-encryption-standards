#!/usr/bin/env python3
"""Automated conformance test harness for yEnc encryption standards v1.1.

Tests conformance against:
- VEC-01: Argon2id key derivation fixtures (argon2id.json)
- VEC-02: HMAC-SHA256 nonce and tweak derivations (nonce_tweak.json)
- VEC-03: XChaCha20-Poly1305 body encryption round-trips (body_encryption.json)
- VEC-04: NIST SP 800-38G FF1 control-line encryption round-trips (control_line_encryption.json)
- VEC-05: Malformed-input rejection and zero-output security (malformed_inputs.json)
- Manifest SHA-256 integrity verification (manifest.json)
"""

import hashlib
import json
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
import nacl.exceptions as ne

try:
    from scripts.generate_conformance_vectors import (
        body_decrypt,
        body_encrypt,
        byte_to_numeral,
        derive_body_nonce,
        derive_control_keys,
        derive_key,
        extract_bootstrap_from_line1,
        ff1_decrypt,
        numeral_to_byte,
        validate_dual_bootstrap,
    )
except ImportError:
    from generate_conformance_vectors import (
        body_decrypt,
        body_encrypt,
        byte_to_numeral,
        derive_body_nonce,
        derive_control_keys,
        derive_key,
        extract_bootstrap_from_line1,
        ff1_decrypt,
        numeral_to_byte,
        validate_dual_bootstrap,
    )


def parse_yencryption_line_v11(line: str) -> dict:
    """Parse and validate the canonical five-token v1.1 =yencryption header."""
    if line != line.strip():
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

    return {
        "cipher": "XChaCha20-Poly1305",
        "salt": bytes.fromhex(salt_hex),
        "index_hex": index_hex,
        "segment_index": segment_index,
        "tag": bytes.fromhex(tag_hex),
    }


class TestConformanceVectors(unittest.TestCase):
    """Automated test suite verifying cryptographic test vectors against v1.1 specifications."""

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

    def test_manifest_checksums(self):
        """Verify SHA-256 integrity hashes and vector counts for all fixtures."""
        self.assertEqual(self.manifest["schema_version"], "1.0")
        self.assertEqual(self.manifest["standard_version"], "1.1")
        expected_files = {
            "argon2id.json",
            "nonce_tweak.json",
            "body_encryption.json",
            "control_line_encryption.json",
            "malformed_inputs.json",
            "nzb_segment_identity.json",
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
            "SALT_MISMATCH",
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
        for case in self.malformed_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                self.assertTrue(case["zero_output_required"])
                if case["category"] == "header_syntax":
                    with self.assertRaises(ValueError):
                        parse_yencryption_line_v11(case["input_line"])
                elif case["category"] == "auth_failure":
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
                elif case["category"] == "control_syntax":
                    if "tampered_salt_hex" in case:
                        with self.assertRaisesRegex(ValueError, "INVALID_SALT_CHARACTER"):
                            extract_bootstrap_from_line1(bytes.fromhex(case["tampered_salt_hex"]) + struct.pack(">I", 1) + b"==")
                    elif "line1_hex" in case:
                        error = "ZERO_SEGMENT_INDEX" if case["expected_error"] == "ZERO_SEGMENT_INDEX" else "LINE_TRUNCATED"
                        with self.assertRaisesRegex(ValueError, error):
                            extract_bootstrap_from_line1(bytes.fromhex(case["line1_hex"]))
                elif case["category"] == "salt_mismatch":
                    params = {
                        "salt": bytes.fromhex(case["header_salt_hex"]),
                        "segment_index": case["header_index"],
                    }
                    with self.assertRaises(ValueError):
                        validate_dual_bootstrap(bytes.fromhex(case["line1_salt_hex"]), case["line1_index"], params)

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
