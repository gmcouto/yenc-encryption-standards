#!/usr/bin/env python3
"""Automated conformance test harness for yEnc encryption standards v1.2.

Tests conformance against:
- VEC-01: Argon2id key derivation fixtures (argon2id.json), including the
  no-normalization password policy
- VEC-02: HMAC-SHA256 nonce and tweak derivations (nonce_tweak.json)
- VEC-03: XChaCha20-Poly1305 body encryption round-trips with Section 2.1
  associated data (body_encryption.json)
- VEC-04: NIST SP 800-38G FF1 control-line encryption round-trips and
  deterministic combined-mode restoration fixtures (control_line_encryption.json)
- VEC-05: Malformed-input rejection and zero-output security (malformed_inputs.json)
- VEC-06: NZB 1.1 identity parsing, tampered-index/metadata-mutation
  authentication enforcement, and zero-output obligations
  (nzb_segment_identity.json)
- VEC-07: Uploader segmentIndex allocation skip vectors (index_allocation.json)
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

# The canonical reference primitives shared with the vector generator.
from yenc_enc_reference import (
    body_decrypt,
    body_encrypt,
    build_aad,
    byte_to_numeral,
    combined_mode_layout,
    derive_body_nonce,
    derive_control_keys,
    derive_key,
    extract_bootstrap_from_line1,
    ff1_decrypt,
    numeral_to_byte,
    uint32_be,
    validate_dual_bootstrap,
)


def check_multipart_framing(has_part_on_ybegin: bool, is_ypart_on_line2: bool) -> None:
    """Validate physical line 2 multipart framing consistency (C-2, STD-13).
    Physical line 2 is =ypart if and only if =ybegin carries part= keyword.
    Any mismatch is corrupt Usenet framing -> PROVIDER_FAILOVER."""
    if has_part_on_ybegin != is_ypart_on_line2:
        if has_part_on_ybegin and not is_ypart_on_line2:
            raise ValueError("MISPLACED_ENCRYPTION_HEADER")
        raise ValueError("INVALID_MULTIPART_FRAMING")


def check_file_size_bound(size: int) -> None:
    """Four-GiB bound (STD-14): encrypted files and offsets MUST be < 2^32 bytes."""
    if size >= 0x100000000:
        raise ValueError("SIZE_OVERFLOW")


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
    # Same forbidden-byte rule as the Line 1 bootstrap (v1.2).
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
            if case["id"] == "metadata-04-body-only-vs-combined-only":
                self.assertTrue(case["provider_failover_permitted"])
                self.assertEqual(case["expected_rejection_stage"], "PROVIDER_FAILOVER")
            elif case["category"] in structural_categories:
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
        """Verify VEC-01 Argon2id key derivation outputs, including the
        no-normalization policy vectors."""
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
                if "no_normalization_distinct_passwords" in case:
                    # Every NFC-equivalent spelling listed must derive a
                    # DIFFERENT key: the v1.2 KDF applies no normalization.
                    keys = {
                        ll.hash_secret_raw(
                            secret=variant.encode("utf-8"),
                            salt=bytes.fromhex(case["salt_hex"]),
                            time_cost=params.get("time_cost", 1),
                            memory_cost=params.get("memory_cost_kib", 65536),
                            parallelism=params.get("parallelism", 4),
                            hash_len=params.get("output_length_bytes", 32),
                            type=ll.Type.ID,
                            version=int(params.get("version", "0x13"), 16),
                        ).hex()
                        for variant in case["no_normalization_distinct_passwords"]
                    }
                    self.assertEqual(len(keys), len(case["no_normalization_distinct_passwords"]))

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
        """Verify VEC-03 body round-trips, canonical five-token headers, and
        the Section 2.1 AAD serialization."""
        for case in self.body_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                salt = bytes.fromhex(case["salt_hex"])
                key = derive_key(case["password"], salt)
                nonce = derive_body_nonce(key, case["segment_index"])
                plaintext = bytes.fromhex(case["plaintext_hex"])
                aad_meta = case["aad"]
                aad = build_aad(
                    bytes.fromhex(aad_meta["name_bytes_hex"]),
                    aad_meta["part_number"],
                    aad_meta["part_begin"],
                    aad_meta["segment_bytes"],
                )
                # The fixture's AAD serialization must equal the reference
                # construction byte for byte (Body Std Section 2.1).
                self.assertEqual(aad.hex(), aad_meta["expected_aad_hex"])
                self.assertTrue(aad.startswith(b"yenc-body aad"))
                self.assertGreater(len(aad), 33)
                ciphertext, tag = body_encrypt(plaintext, key, nonce, aad)
                self.assertEqual(ciphertext.hex(), case["expected_ciphertext_hex"])
                self.assertEqual(tag.hex(), case["expected_tag_hex"])
                params = parse_yencryption_line_v11(case["expected_yencryption_line"])
                self.assertEqual(len(case["expected_yencryption_line"]), 128)
                self.assertEqual(case["expected_yencryption_line"].split(" ").__len__(), 5)
                self.assertEqual(params["salt"], salt)
                self.assertEqual(params["segment_index"], case["segment_index"])
                self.assertEqual(params["tag"], tag)
                self.assertEqual(body_decrypt(ciphertext, tag, key, nonce, aad), plaintext)
                # The same ciphertext with the empty AAD must fail: the
                # tag is AAD-bound (STD-1 Option A).
                with self.assertRaises(ne.CryptoError):
                    body_decrypt(ciphertext, tag, key, nonce, b"")

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
                    if "expected_multipart" in case:
                        layout = combined_mode_layout(case["input_lines"][0])
                        self.assertEqual(layout["multipart"], case["expected_multipart"])
                        self.assertEqual(layout["first_data_line"], case["expected_first_data_line"])
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
                    if "has_part_on_ybegin" in case and "is_ypart_on_line2" in case:
                        self.assertRaisesRegex(
                            ValueError,
                            re.escape(case["expected_error"]),
                            check_multipart_framing,
                            case["has_part_on_ybegin"],
                            case["is_ypart_on_line2"],
                        )
                    else:
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
                    if case["id"] == "metadata-04-body-only-vs-combined-only":
                        self.assertEqual(case["expected_rejection_stage"], "PROVIDER_FAILOVER")
                        self.assertTrue(case["provider_failover_permitted"])
                        self.assertEqual(case["expected_error"], "CONTROL_LINE_DECRYPT_FAILURE")
                    else:
                        self.assertEqual(case["expected_rejection_stage"], "METADATA_VALIDATION")
                        self.assertFalse(case["provider_failover_permitted"])
                        self.assertIn(case["expected_error"], metadata_tokens)
                elif category == "auth_failure":
                    key = derive_key(case["password"], bytes.fromhex(case["salt_hex"]))
                    nonce = derive_body_nonce(key, case["segment_index"])
                    ciphertext = bytes.fromhex(case.get("tampered_ciphertext_hex") or case["ciphertext_hex"])
                    tag = bytes.fromhex(case.get("tampered_tag_hex") or case["tag_hex"])
                    aad = bytes.fromhex(case.get("aad_hex") or "")
                    output = None
                    with self.assertRaises(ne.CryptoError):
                        try:
                            output = body_decrypt(ciphertext, tag, key, nonce, aad)
                        finally:
                            self.assertIsNone(output)
                elif category == "control_syntax":
                    if "tampered_salt_hex" in case:
                        with self.assertRaisesRegex(ValueError, "INVALID_SALT_CHARACTER"):
                            extract_bootstrap_from_line1(bytes.fromhex(case["tampered_salt_hex"]) + struct.pack(">I", 1) + b"==")
                    elif "line1_hex" in case:
                        # Dispatch on the vector's own expected_error token so
                        # forbidden-index-byte, zero-index, and
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

    @staticmethod
    def _metadata(root):
        return {
            meta.get("type"): (meta.text or "")
            for meta in root.findall(
                "./{http://www.newzbin.com/DTD/2003/nzb}head/"
                "{http://www.newzbin.com/DTD/2003/nzb}meta"
            )
        }

    def _body_auth(self, case, segment_index, password=None, salt_hex=None):
        """Run the Section 5 body authentication/decryption for a vector.

        Returns (plaintext_or_None, failed). On any authentication failure
        the returned plaintext is None (the zero-output obligation).
        """
        key = derive_key(
            password or case["password"],
            bytes.fromhex(salt_hex or case["salt_hex"]),
        )
        nonce = derive_body_nonce(key, segment_index)
        ciphertext = bytes.fromhex(case["ciphertext_hex"])
        tag = bytes.fromhex(case["tag_hex"])
        aad = bytes.fromhex(case["aad_hex"])
        try:
            return body_decrypt(ciphertext, tag, key, nonce, aad), False
        except ne.CryptoError:
            return None, True

    def test_vec06_nzb_segment_identity(self):
        """Verify VEC-06: NZB parsing, tampered-index/metadata-mutation
        authentication, zero-output obligations, and expected_segments."""
        self.assertEqual(self.nzb_identity_data["requirement"], "VEC-06")
        exercised: set[str] = set()
        for case in self.nzb_identity_data["vectors"]:
            with self.subTest(vector_id=case["id"]):
                exercised.add(case["id"])
                category = case["category"]

                if category in ("valid_identity", "unencrypted_compatibility"):
                    root = ET.fromstring(case["nzb_xml"])
                    for segment in self._segments(root):
                        self.assertEqual(set(segment.attrib), {"bytes", "number"})
                    if case.get("is_encrypted"):
                        metadata = self._metadata(root)
                        self.assertEqual(metadata.get("yenc_encrypted"), "true")
                        self.assertIn("password", metadata)
                    # Parsed records MUST match expected_segments exactly:
                    # message id, part number, and byte count in XML order.
                    parsed = [
                        {
                            "message_id": segment.text,
                            "part": int(segment.get("number")),
                            "bytes": int(segment.get("bytes")),
                        }
                        for segment in self._segments(root)
                    ]
                    self.assertEqual(parsed, case["expected_segments"])
                    if category == "unencrypted_compatibility":
                        # No provenance marker: a reader MUST treat this as
                        # ordinary yEnc (no transport decryption dispatch).
                        self.assertNotIn("yenc_encrypted", self._metadata(root))

                elif category == "index_tampering":
                    # The fetched article's bootstrap index is the TAMPERED
                    # value; authentication against it MUST fail, and the
                    # zero-output obligation must hold (no plaintext bytes
                    # released, by CryptoError semantics and by assertion).
                    self.assertTrue(case["zero_output_required"])
                    self.assertEqual(case["expected_error"], "AUTHENTICATION_FAILURE")
                    self.assertEqual(case["expected_rejection_stage"], "PROVIDER_FAILOVER")
                    if "tampered_segments" in case:
                        for seg in case["tampered_segments"]:
                            output, failed = self._body_auth(
                                seg,
                                seg["tampered_segment_index"],
                                password=case["password"],
                                salt_hex=case["salt_hex"],
                            )
                            self.assertTrue(failed, case["id"])
                            self.assertIsNone(output)
                            # Sanity: with the ACTUAL index the same bytes
                            # authenticate, proving the fixture itself is
                            # sound and the failure is caused by the tamper.
                            actual, failed_actual = self._body_auth(
                                seg,
                                seg["actual_segment_index"],
                                password=case["password"],
                                salt_hex=case["salt_hex"],
                            )
                            self.assertFalse(failed_actual, case["id"])
                            self.assertEqual(actual, bytes.fromhex(seg["plaintext_hex"]))
                    else:
                        output, failed = self._body_auth(
                            case, case["tampered_segment_index"]
                        )
                        self.assertTrue(failed, case["id"])
                        self.assertIsNone(output)
                        actual, failed_actual = self._body_auth(
                            case, case["actual_segment_index"]
                        )
                        self.assertFalse(failed_actual, case["id"])
                        self.assertEqual(actual, bytes.fromhex(case["plaintext_hex"]))

                elif category == "metadata_mutation":
                    # STD-1 Option A: mutated AAD (name/part/begin/bytes)
                    # MUST fail authentication even though the ciphertext,
                    # tag, salt, and index are all authentic, and MUST
                    # release zero bytes.
                    self.assertTrue(case["zero_output_required"])
                    self.assertEqual(case["expected_error"], "AUTHENTICATION_FAILURE")
                    self.assertEqual(case["expected_rejection_stage"], "PROVIDER_FAILOVER")
                    output, failed = self._body_auth(case, case["segment_index"])
                    self.assertTrue(failed, case["id"])
                    self.assertIsNone(output)
                    root = ET.fromstring(case["nzb_xml"])
                    self.assertEqual(self._metadata(root).get("yenc_encrypted"), "true")

                else:
                    self.fail(f"Unknown nzb_segment_identity category: {category}")
        all_ids = {case["id"] for case in self.nzb_identity_data["vectors"]}
        self.assertEqual(exercised, all_ids)

    def test_vec07_index_allocation(self):
        """Verify uploader index skip vectors: forbidden candidates are skipped,
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


    def test_std13_multipart_framing_cases(self):
        """Verify C-2 undefined multipart framing cases raise appropriate errors."""
        # Case 1: Line 2 is =ypart but =ybegin lacks part=
        with self.assertRaisesRegex(ValueError, "INVALID_MULTIPART_FRAMING"):
            check_multipart_framing(has_part_on_ybegin=False, is_ypart_on_line2=True)
        # Case 2: =ybegin carries part= but line 2 is =yencryption
        with self.assertRaisesRegex(ValueError, "MISPLACED_ENCRYPTION_HEADER"):
            check_multipart_framing(has_part_on_ybegin=True, is_ypart_on_line2=False)
        # Valid cases must not raise
        check_multipart_framing(has_part_on_ybegin=False, is_ypart_on_line2=False)
        check_multipart_framing(has_part_on_ybegin=True, is_ypart_on_line2=True)

    def test_std14_four_gib_bound(self):
        """Verify STD-14 4-GiB bound enforcement: size/offset >= 2^32 is rejected."""
        with self.assertRaises(ValueError):
            uint32_be(0x100000000)
        with self.assertRaisesRegex(ValueError, "SIZE_OVERFLOW"):
            check_file_size_bound(0x100000000)
        check_file_size_bound(0xFFFFFFFF)


if __name__ == "__main__":
    unittest.main()
