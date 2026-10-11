#!/usr/bin/env python3
"""Automated specification validation test harness for yEnc encryption standards v1.2.

Tests conformance against:
- BOOTSTRAP-SPEC-01: Control line 20-byte bootstrap prefix and 5-token canonical grammar
- BOOTSTRAP-SPEC-02: Standard NZB 1.1 segments with identity carried in article bytes
- SPEC-01: Control line bootstrap carriage and length preservation rules
- SPEC-02: 1-based physical lineIndex counting and 253-byte alphabet numeral bijection
- SPEC-03: Big-endian uint32_be integer serialization in HMAC-SHA256 derivations
- SPEC-04: Specification version v1.2, metadata headers, and synchronized documentation
"""

import re
import unittest
from pathlib import Path


class TestStandardsV1(unittest.TestCase):
    """Specification validation suite checking wire contracts against normative spec files."""

    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parent.parent
        cls.standards_dir = cls.repo_root / "yenc-encryption-standards"
        if not cls.standards_dir.exists() or not (cls.standards_dir / "yEnc Body Encryption Standard.txt").exists():
            cls.standards_dir = cls.repo_root
        cls.body_spec_path = cls.standards_dir / "yEnc Body Encryption Standard.txt"
        cls.control_spec_path = cls.standards_dir / "yEnc Control Lines Encryption Standard.txt"
        cls.readme_path = cls.standards_dir / "README.md"

        if cls.body_spec_path.exists():
            cls.body_spec = cls.body_spec_path.read_text(encoding="utf-8")
        else:
            cls.body_spec = ""

        if cls.control_spec_path.exists():
            cls.control_spec = cls.control_spec_path.read_text(encoding="utf-8")
        else:
            cls.control_spec = ""

        if cls.readme_path.exists():
            cls.readme = cls.readme_path.read_text(encoding="utf-8")
        else:
            cls.readme = ""

    def test_spec_environment(self):
        """Verify that all three specification files exist and contain non-empty UTF-8 text."""
        self.assertTrue(self.body_spec_path.is_file(), f"Missing {self.body_spec_path}")
        self.assertTrue(self.control_spec_path.is_file(), f"Missing {self.control_spec_path}")
        self.assertTrue(self.readme_path.is_file(), f"Missing {self.readme_path}")
        self.assertGreater(len(self.body_spec), 0, "Body specification file is empty")
        self.assertGreater(len(self.control_spec), 0, "Control lines specification file is empty")
        self.assertGreater(len(self.readme), 0, "README file is empty")

    def assert_plain_segments(self, text):
        """Every <segment> tag in text carries only the NZB 1.1 bytes and number attributes."""
        tags = re.findall(r"<segment\s([^>]*)>", text)
        for attrs in tags:
            self.assertEqual(set(re.findall(r"(\w+)=", attrs)), {"bytes", "number"}, attrs)

    def test_spec01_salt_carriage(self):
        """Verify SPEC-01 and BOOTSTRAP-SPEC-01: 20-byte prepended bootstrap on line 1, length properties, and removal of stale text."""
        # Must mandate 20-byte prepended bootstrap prefix on line 1
        self.assertRegex(self.control_spec, r"prepend the 20-byte (?:article )?bootstrap")

        # Must document that first line expands by 20 bytes while lines 2..N preserve length
        self.assertRegex(
            self.control_spec,
            r"(?s)(?:first.*control line|lineIndex=1).*?expands?\s+by\s+(?:exactly\s+)?20\s+bytes",
        )
        self.assertRegex(
            self.control_spec,
            r"(?s)(?:subsequent|lines?\s+2\.\.N|lineIndex\s*>\s*1).*?(?:identical\s+length|preserve\s+exact.*length)",
        )

        # Must specify overall block length increases by 20 bytes
        self.assertRegex(
            self.control_spec,
            r"(?s)[Oo]verall yEnc block length increases by (?:exactly )?20 bytes",
        )

        # Must specify data lines remain completely unchanged
        self.assertIn("Data lines remain completely unchanged", self.control_spec)

        # Must NOT contain stale v0.2 claims
        self.assertNotIn("Each encrypted yEnc control line has identical length", self.control_spec)
        self.assertNotIn(
            "No additional salt storage is required as salt is deterministically derived",
            self.control_spec,
        )
        self.assertNotIn("Overall yEnc block length is preserved exactly", self.control_spec)

    def test_spec02_line_index_rules(self):
        """Verify SPEC-02: 1-based physical line counting, 253-byte alphabet numeral bijection."""
        # Must define lineIndex as 1-based physical line number across all lines
        self.assertIn("1-based", self.control_spec)
        self.assertIn("physical line", self.control_spec)

        # Must define canonical 253-byte Alphabet numeral bijection table (mapping bytes to 0..252)
        self.assertIn("0x01", self.control_spec)
        self.assertIn("0x09", self.control_spec)
        self.assertIn("0x0B", self.control_spec)
        self.assertIn("0x0C", self.control_spec)
        self.assertIn("0x0E", self.control_spec)
        self.assertIn("0xFF", self.control_spec)
        self.assertRegex(self.control_spec, r"b\s*-\s*1")
        self.assertRegex(self.control_spec, r"b\s*-\s*3")

        # Must ensure procedural loop steps increment on every physical line
        self.assertNotIn(
            "Increment lineIndex\n   b. For lines not beginning with \"=y\"",
            self.control_spec,
        )
        self.assertRegex(
            self.control_spec,
            r"increment lineIndex (?:sequentially )?on every physical line|incrementing lineIndex on every physical line",
        )

    def test_spec03_control_endianness(self):
        """Verify SPEC-03 for control lines: uint32_be big-endian serialization in tweak derivation."""
        self.assertIn("uint32_be", self.control_spec)
        self.assertRegex(self.control_spec, r"big-endian|network byte order")

        # Fixed 26-byte HMAC input layout: ASCII "yenc-control tweak" (18B) + uint32_be(segmentIndex) (4B) + uint32_be(lineIndex) (4B)
        self.assertIn("yenc-control tweak", self.control_spec)
        self.assertIn("uint32_be(segmentIndex)", self.control_spec)
        self.assertIn("uint32_be(lineIndex)", self.control_spec)
        self.assertRegex(self.control_spec, r"26 bytes?")

        # encKey derivation uses 16 bytes ASCII prefix "yenc-control key"
        self.assertIn("yenc-control key", self.control_spec)

    def test_spec03_endianness_specified(self):
        """Verify SPEC-03 across all specs: 4-byte big-endian (uint32_be) integer serialization."""
        self.assertIn("uint32_be", self.body_spec)
        self.assertIn("uint32_be", self.control_spec)
        self.assertRegex(self.body_spec, r"big-endian|network byte order")
        self.assertRegex(self.control_spec, r"big-endian|network byte order")

    def test_spec04_control_version(self):
        """Verify SPEC-04 and BOOTSTRAP-SPEC-01 for control lines: Version 1.2, experimental wire contract, updated date, and Change Log."""
        self.assertIn("SPECIFICATION: yEnc Control Lines Encryption Standard", self.control_spec)
        self.assertIn("Version: 1.2", self.control_spec)
        self.assertRegex(self.control_spec, r"Date:\s+2026-10-10")
        self.assertIn("Status: Experimental Wire Contract (v1.2)", self.control_spec)
        self.assertIn("Category: Standards Track", self.control_spec)
        self.assertIn("Version 1.2 (2026-10-10):", self.control_spec)

    def test_spec04_body_version(self):
        """Verify SPEC-04 and BOOTSTRAP-SPEC-01 for body encryption: Version 1.2, experimental wire contract, updated date, and Change Log."""
        self.assertIn("SPECIFICATION: yEnc Body Encryption Standard", self.body_spec)
        self.assertIn("Version: 1.2", self.body_spec)
        self.assertRegex(self.body_spec, r"Date:\s+2026-10-10")
        self.assertIn("Status: Experimental Wire Contract (v1.2)", self.body_spec)
        self.assertIn("Category: Standards Track", self.body_spec)
        self.assertIn("Version 1.2 (2026-10-10):", self.body_spec)

    def test_spec04_version_frozen(self):
        """Verify SPEC-04 across all specs: Version 1.2, experimental wire contract, updated date, and Change Log."""
        for spec_text in (self.body_spec, self.control_spec):
            self.assertIn("Version: 1.2", spec_text)
            self.assertIn("Status: Experimental Wire Contract (v1.2)", spec_text)
            self.assertRegex(spec_text, r"Date:\s+2026-10-10")
            self.assertIn("Version 1.2 (2026-10-10):", spec_text)

    def test_spec04_readme_synchronized(self):
        """Verify SPEC-04 README synchronization: status badge and no obsolete deterministic salt text."""
        self.assertNotIn("(deterministic)", self.readme)
        self.assertIn("v1.2 Experimental", self.readme)

    def test_spec05_nzb_segment_index_extension(self):
        """Verify BOOTSTRAP-SPEC-02: Section 8 requires standard NZB 1.1 segments with identity in article bytes."""
        for spec in (self.body_spec, self.control_spec):
            sec8_match = re.search(r"8\. NZB File Requirements.*?(?=9\. Interoperability)", spec, re.S)
            self.assertIsNotNone(sec8_match)
            sec8 = sec8_match.group(0)
            self.assertIn('<meta type="password">', sec8)
            self.assertIn('<meta type="yenc_encrypted">true</meta>', sec8)
            self.assertIn("<segment", sec8)
            self.assert_plain_segments(sec8)
            self.assertRegex(sec8, r"(?i)carries no encryption-specific segment data")

            self.assertIn("segmentIndex", spec)
            self.assertIn("1..=4294967295", spec)

    def test_spec05_nzb_identity_control(self):
        """Verify REQ-11-02 and BOOTSTRAP-SPEC-02 for control lines: segmentIndex in Section 2, 3, 4, 5, 8, and 10 with standard NZB 1.1."""
        sec2 = re.search(r"2\. Definitions.*?(?=3\. Processing Procedure)", self.control_spec, re.S)
        self.assertIsNotNone(sec2)
        self.assertIn("segmentIndex", sec2.group(0))
        self.assertIn("1..=4294967295", sec2.group(0))

        sec3 = re.search(r"3\. Processing Procedure.*?(?=4\. Encryption Algorithm)", self.control_spec, re.S)
        self.assertIsNotNone(sec3)
        self.assertIn("segmentIndex", sec3.group(0))

        sec4 = re.search(r"4\. Encryption Algorithm.*?(?=5\. Decryption(?: and Error Handling| Algorithm))", self.control_spec, re.S)
        self.assertIsNotNone(sec4)
        self.assertIn("uint32_be(segmentIndex)", sec4.group(0))

        sec5 = re.search(r"5\. Decryption(?: Algorithm| and Error Handling).*?(?=6\. Length Properties)", self.control_spec, re.S)
        self.assertIsNotNone(sec5)
        self.assertIn("segmentIndex", sec5.group(0))

        sec8 = re.search(r"8\. NZB File Requirements.*?(?=9\. Interoperability(?: & Transport)? (?:Notes|Considerations))", self.control_spec, re.S)
        self.assertIsNotNone(sec8)
        self.assertIn("segmentIndex", sec8.group(0))
        self.assertIn("<segment", sec8.group(0))
        self.assert_plain_segments(sec8.group(0))

        sec10 = re.search(r"10\. Example.*?(?=11\. Summary)", self.control_spec, re.S)
        self.assertIsNotNone(sec10)
        self.assertIn("segmentIndex", sec10.group(0))
        self.assert_plain_segments(sec10.group(0))

    def test_spec05_nzb_identity_body(self):
        """Verify REQ-11-02 and BOOTSTRAP-SPEC-02 for body encryption: segmentIndex in Section 2, 3, 4, 5, 8, 10, zero-output."""
        sec2 = re.search(r"2\. Definitions.*?(?=3\. Processing Procedure)", self.body_spec, re.S)
        self.assertIsNotNone(sec2)
        self.assertIn("segmentIndex", sec2.group(0))
        self.assertIn("1..=4294967295", sec2.group(0))

        sec3 = re.search(r"3\. Processing Procedure.*?(?=4\. Encryption Algorithm)", self.body_spec, re.S)
        self.assertIsNotNone(sec3)
        self.assertIn("segmentIndex", sec3.group(0))

        sec4 = re.search(r"4\. Encryption Algorithm.*?(?=5\. Decryption(?: and Error Handling| Algorithm))", self.body_spec, re.S)
        self.assertIsNotNone(sec4)
        self.assertIn("uint32_be(segmentIndex)", sec4.group(0))

        sec5 = re.search(r"5\. Decryption(?: Algorithm| and Error Handling).*?(?=6\. Length Properties)", self.body_spec, re.S)
        self.assertIsNotNone(sec5)
        self.assertIn("segmentIndex", sec5.group(0))
        self.assertIn("Poly1305 authentication tag verification failure", sec5.group(0))

        sec8 = re.search(r"8\. NZB File Requirements.*?(?=9\. Interoperability(?: & Transport)? (?:Notes|Considerations))", self.body_spec, re.S)
        self.assertIsNotNone(sec8)
        self.assertIn("segmentIndex", sec8.group(0))
        self.assertIn("<segment", sec8.group(0))
        self.assert_plain_segments(sec8.group(0))

        sec10 = re.search(r"10\. Example.*?(?=11\. Summary)", self.body_spec, re.S)
        self.assertIsNotNone(sec10)
        self.assertIn("segmentIndex", sec10.group(0))
        self.assert_plain_segments(sec10.group(0))

    def test_spec05_producer_consumer_rules(self):
        """Verify BOOTSTRAP-SPEC-02: producer/consumer obligations in Section 8 of both specifications for standard NZB 1.1."""
        for spec in (self.body_spec, self.control_spec):
            sec8_match = re.search(r"8\. NZB File Requirements.*?(?=9\. Interoperability(?: & Transport)? (?:Notes|Considerations))", spec, re.S)
            self.assertIsNotNone(sec8_match)
            sec8 = sec8_match.group(0)

            self.assertIn('<meta type="yenc_encrypted">true</meta>', sec8)
            self.assertIn('<meta type="password">', sec8)
            self.assertRegex(sec8, r"Emit standard NZB 1\.1 <segment> elements|Standard NZB 1\.1 Segments")
            self.assertRegex(sec8, r"[Aa]ssign indices continuously starting from 1")
            self.assertRegex(sec8, r"[Uu]nique (?:segmentIndex|value) within the upload")
            self.assertRegex(sec8, r"[Pp]reserve an article's assigned index across retries")

            self.assertRegex(sec8, r"[Ee]xtract segmentIndex and salt directly from fetched article bootstrap")
            self.assertRegex(sec8, r"(?:file )?subject.*?no cryptographic meaning")
            self.assertRegex(sec8, r"XML (?:file|segment) order.*?no cryptographic meaning")

    def test_spec05_spec_sections_updated(self):
        """Verify REQ-11-02: Sections 2, 3, 4, 5, 8, and 10 exist and contain explicit segmentIndex references."""
        for spec in (self.body_spec, self.control_spec):
            for sec_num, sec_title, next_sec in [
                ("2", "Definitions", "3. Processing Procedure"),
                ("3", "Processing Procedure", "4. Encryption Algorithm"),
                ("4", "Encryption Algorithm", "5. Decryption"),
                ("5", "Decryption", "6. Length Properties"),
                ("8", "NZB File Requirements", "9. Interoperability"),
                ("10", "Example", "11. Summary"),
            ]:
                pattern = rf"{sec_num}\.\s+{sec_title}.*?(?={re.escape(next_sec)})"
                sec_match = re.search(pattern, spec, re.S)
                self.assertIsNotNone(sec_match, f"Missing Section {sec_num} in specification")
                self.assertIn(
                    "segmentIndex",
                    sec_match.group(0),
                    f"Section {sec_num} ({sec_title}) does not reference segmentIndex",
                )

    def test_spec05_readme_sync(self):
        """Verify REQ-11-03 and BOOTSTRAP-SPEC-02: README synchronization with segmentIndex, 1..=4294967295, and standard NZB 1.1."""
        self.assertIn("segmentIndex", self.readme)
        self.assertIn("1..=4294967295", self.readme)
        self.assertIn("v1.2 Experimental", self.readme)

    def test_spec06_provenance_and_archive_password_schema(self):
        """Verify encrypted transport provenance is explicit and archive passwords stay decoupled."""
        for name, spec in (("body", self.body_spec), ("control", self.control_spec)):
            section = re.search(r"8\. NZB File Requirements.*?(?=9\. Interoperability)", spec, re.S)
            self.assertIsNotNone(section, f"Missing NZB requirements section in {name} standard")
            text = section.group(0)
            self.assertIn('<meta type="yenc_encrypted">true</meta>', text)
            self.assertIn('<meta type="password">', text)
            self.assertRegex(text, r"(?is)password.{0,160}archive|archive.{0,160}password")
            self.assertRegex(text, r"(?is)tag is missing.{0,120}standard unencrypted")

        self.assertIn('<meta type="yenc_encrypted">true</meta>', self.readme)
        self.assertRegex(self.readme, r"password.*without.*yenc_encrypted.*archive|yenc_encrypted.*password.*archive")

    def test_spec07_body_wire_contract(self):
        """Verify body grammar, placement, salts, CRC normalization, and error tiers in scoped sections."""
        procedure = re.search(r"3\. Processing Procedure.*?(?=4\. Encryption Algorithm)", self.body_spec, re.S).group(0)
        decryption = re.search(r"5\. Decryption.*?(?=6\. Length Properties)", self.body_spec, re.S).group(0)
        self.assertRegex(procedure, r"line 2.*=yencryption|=yencryption.*line 2")
        self.assertIn("line 3", procedure)
        self.assertIn("five tokens", decryption)
        self.assertIn("lowercase", decryption)
        self.assertRegex(decryption, r"(?i)dual-bootstrap|dual-salt")
        self.assertIn("crc32 = None", decryption)
        self.assertIn("Non-Retriable Structural Failures", decryption)
        self.assertIn("Retriable Provider Corruption Failures", decryption)
        self.assertIn("bounded", self.body_spec)
        self.assertIn("no cryptographic meaning", self.body_spec)

    def test_spec07_control_wire_contract(self):
        """Verify control-line salt, placement, failure, and identity rules in scoped sections."""
        procedure = re.search(r"3\. Processing Procedure.*?(?=4\. Encryption Algorithm)", self.control_spec, re.S).group(0)
        decryption = re.search(r"5\. Decryption.*?(?=6\. Length Properties)", self.control_spec, re.S).group(0)
        self.assertIn("dot-unstuffing", procedure)
        self.assertRegex(decryption, r"(?i)dual-bootstrap|dual-salt")
        self.assertIn("five-token grammar", decryption)
        self.assertIn("line 2", decryption)
        self.assertIn("line 3", decryption)
        self.assertIn("Non-Retriable Structural Failures", self.control_spec)
        self.assertIn("Retriable Provider Corruption Failures", self.control_spec)
        self.assertIn("no cryptographic meaning", self.control_spec)

    def test_spec07_canonical_yencryption_grammar(self):
        """Verify BOOTSTRAP-SPEC-01: canonical 5-token wire grammar and synchronized references."""
        abnf = (
            'yencryption = "=yencryption" SP\n'
            '                  "cipher=XChaCha20-Poly1305" SP\n'
            '                  "salt=" 32HEXDIG-LOWER SP\n'
            '                  "index=" 8HEXDIG-LOWER SP\n'
            '                  "tag=" 32HEXDIG-LOWER'
        )
        wire_form = "=yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>"
        self.assertIn(abnf, self.body_spec)
        self.assertIn("HEXDIG-LOWER = DIGIT / %x61-66", self.body_spec)
        for text in (self.body_spec, self.control_spec, self.readme):
            self.assertIn(wire_form, text)
        for stale_form in (
            "salt=<32_hex> tag=<32_hex>",
            "exact four tokens lowercase grammar",
            "strict four tokens lowercase grammar",
            "exactly four tokens",
            "exact four tokens",
        ):
            self.assertNotIn(stale_form, self.body_spec)
            self.assertNotIn(stale_form, self.control_spec)

    def test_spec07_error_tiers_are_source_based(self):
        """Verify article syntax defects cannot overlap structural metadata errors."""
        for spec in (self.body_spec, self.control_spec):
            decryption = re.search(r"5\. Decryption.*?(?=6\. Length Properties)", spec, re.S).group(0)
            structural, provider = decryption.split("2. Retriable Provider Corruption Failures:", 1)
            self.assertIn("Malformed NZB XML", structural)
            self.assertNotIn("Malformed =yencryption", structural)
            self.assertNotIn("Dual-salt mismatch", structural)
            self.assertRegex(provider, r"(?i)malformed.*control lines|canonical.*grammar")
            self.assertRegex(provider, r"(?i)dual-salt|dual-index|dual-bootstrap")
            self.assertIn("unsupported", provider)

    def test_spec07_article_bounded_memory_guidance(self):
        """Verify the normative memory bound and observed implementation range."""
        for text in (self.body_spec, self.control_spec, self.readme):
            self.assertIn("O(article_size)", text)
            self.assertIn("128 KiB", text)
            self.assertIn("4 MiB", text)
            self.assertIn("8 MiB", text)
            self.assertRegex(text, r"(?s)MUST NOT (?:accumulate|grow with).*?(?:multipart file|release)")
            self.assertRegex(text, r"implementation guidance, not wire(?:-format)? limits")
        self.assertNotIn("~750KB-2MB", self.body_spec)
        self.assertNotIn("~750KB-2MB", self.control_spec)
        self.assertNotIn("~750KB to 2MB", self.readme)

    def test_spec05_humanizer_checks(self):
        """Verify REQ-11-05: absence of em dashes and en dashes in specification files."""
        for path, text in (
            (self.body_spec_path, self.body_spec),
            (self.control_spec_path, self.control_spec),
            (self.readme_path, self.readme),
        ):
            self.assertNotIn("\u2014", text, f"Em dash found in {path.name}")
            self.assertNotIn("\u2013", text, f"En dash found in {path.name}")


if __name__ == "__main__":
    unittest.main()
