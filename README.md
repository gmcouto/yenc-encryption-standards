# yEnc Encryption Standards

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Experimental Wire Contract (v1.2)](https://img.shields.io/badge/Status-v1.2%20Experimental-blue.svg)]()

This repository contains specifications for two encryption standards for yEnc-encoded binary blocks used in Usenet transfers. Version 1.2 defines the two standards for use together; an upload is either encrypted with both or not encrypted at all.

## Standards Overview

### 1. yEnc Control Lines Encryption Standard

This standard obfuscates and protects metadata. It targets the yEnc header and footer lines (lines beginning with "=y") and uses FF1 Format-Preserving Encryption.

Encrypted control lines keep the exact length (lines 2..N) and character compatibility. The first control line (lineIndex=1) expands by 20 bytes because of the prepended article bootstrap (16-byte raw salt from the 253-byte Alphabet and 4-byte big-endian uint32 segmentIndex); the expansion is measured on line content, excluding any trailing line terminator, and bootstrap extraction happens after NNTP dot-unstuffing. Only metadata is encrypted; binary data lines remain completely untouched. File names, sizes, part information, and yEnc structure are hidden. Line counting uses 1-based physical line numbers after NNTP dot-unstuffing. Line terminators are preserved byte-for-byte on reconstruction (bare LF is never canonicalized to CRLF). Decoding is deterministic and position-based: header positions are inferred from the restored structure and data lines are never decrypted.

### 2. yEnc Body Encryption Standard

This standard protects content with authentication. It targets binary file data before yEnc encoding and uses XChaCha20-Poly1305 Authenticated Encryption.

It encrypts the actual file data and detects tampering through cryptographic authentication; failed authentication results in complete decryption failure with zero partial data output. Each encryption binds exact associated data (AAD): the segment's part number, part begin offset, segment byte count, and the `=ybegin` name value, serialized as `"yenc-body aad" || uint32_be(partNumber) || uint32_be(partBegin) || uint64_be(segmentBytes) || uint32_be(nameLength) || name` (Body Standard Section 2.1). This binds every segment to its position in the assembled file, so segment substitution, replay, or repositioning fails authentication; NNTP headers, subjects, Message-IDs, and XML order remain outside the AEAD and are explicitly unauthenticated. The canonical format is a strict five-token control line `=yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>` in lowercase hex (128 characters). Placement is physical line 2 for single-part articles (immediately after `=ybegin`) and physical line 3 for multipart articles (immediately after `=ypart`). An article is multipart if and only if physical line 2 after `=ybegin` is `=ypart`; otherwise it is single-part. The wire CRC covers ciphertext and is verified before AEAD decryption; after authentication succeeds, decoders MUST either clear the CRC metadata (crc32 = None) or recompute it over authenticated plaintext so downstream consumers verify plaintext CRC.

## Usage Scenarios

Version 1.2 defines combined mode only (control line encryption and body encryption together); other framing modes are reserved for future standards. For protection of both content and metadata, apply both standards together. With both standards in use, the 16-byte raw salt and 4-byte big-endian segmentIndex from Line 1 MUST equal the 16-byte salt and 8-hex index carried in `=yencryption` byte-for-byte and value-for-value; because one salt is shared, the combined-mode salt MUST lie in the intersection of both domains (the 253-byte Alphabet, with bytes 0x00, 0x0A, and 0x0D excluded). v1.2 producers emit combined mode only; receivers MUST support combined mode and reject other modes under PROVIDER_FAILOVER. An upload that needs neither protection is ordinary yEnc and uses neither standard.

## Body Encryption vs. Preprocessing

Body encryption is an alternative to preprocessing encryption such as password-protected archives, not an addition to it. Encrypting each segment while the article is built has these practical advantages:

- **No intermediate files**: no encrypted copy of the release is written to disk first, so no extra storage is needed and nothing has to be cleaned up afterwards.
- **Streaming**: encryption happens in the same pass as yEnc encoding, with memory bounded to one article regardless of file size.
- **Authenticated**: Poly1305 detects any modification, so tampered or corrupted articles are rejected instead of producing damaged output.
- **One password**: both standards use the same password, with domain-separated key derivation, so the NZB carries a single password.

## Password Management and Canonical NZB Metadata

### Transport Provenance vs Archive Passwords

To distinguish encrypted yEnc transport from unencrypted uploads carrying archive passwords (such as password-protected RAR or 7z files), compliant NZB documents carry explicit metadata flags:

1. Encrypted Transport: When yEnc encryption is present, the NZB `<head>` MUST contain `<meta type="yenc_encrypted">true</meta>`. `<meta type="password">` is the interoperable way to deliver the transport password. Clients MAY also take the password from their own sources (user input, API, configuration) and let it override the NZB value; how a client obtains, stores, or displays the password is up to the client.
2. Archive Password Decoupling: If an NZB contains `<meta type="password">` without `<meta type="yenc_encrypted">true</meta>`, the password applies solely to downstream extraction tools. The download client MUST process segments as standard unencrypted yEnc blocks without attempting transport decryption.

### NZB 1.1 Example (Encrypted Release)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">correct horse battery staple</meta>
    <meta type="yenc_encrypted">true</meta>
  </head>
  <file poster="poster@example.com"
       date="1727280000"
       subject="4Qd7sJm2pL yEnc (1/2)">
    <groups>
      <group>alt.binaries.example</group>
    </groups>
    <segments>
      <segment bytes="750000" number="1">article-1@example.com</segment>
      <segment bytes="750000" number="2">article-2@example.com</segment>
    </segments>
  </file>
  <file poster="poster@example.com"
       date="1727280001"
       subject="n8Vx3KaP yEnc (1/1)">
    <groups>
      <group>alt.binaries.example</group>
    </groups>
    <segments>
      <segment bytes="500000" number="1">article-3@example.com</segment>
    </segments>
  </file>
</nzb>
```

### NZB 1.1 Example (Unencrypted Release with Archive Password)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">archive_extraction_password</meta>
  </head>
  <file poster="poster@example.com"
       date="1727280000"
       subject="archive.part01.rar yEnc (1/2)">
    <groups>
      <group>alt.binaries.example</group>
    </groups>
    <segments>
      <segment bytes="750000" number="1">article-rar-1@example.com</segment>
      <segment bytes="750000" number="2">article-rar-2@example.com</segment>
    </segments>
  </file>
</nzb>
```

### Segment Identity Rules

- `number` is the standard NZB 1.1 1-based part number within the file.
- `segmentIndex` is an explicit unsigned 32-bit integer in range `1..=4294967295` encoded in article bootstrap bytes: carried in the `=yencryption` `index` parameter and in Line 1 bytes 16..19.
- Formatting is a 4-byte big-endian integer on Line 1 and an 8-character lowercase hexadecimal string in =yencryption.
- Each segmentIndex is globally unique across the entire upload session.
- Index framing rule: producers MUST skip any `segmentIndex` whose 4-byte big-endian representation contains bytes `0x0A` (LF) or `0x0D` (CR); receivers MUST reject such indices under `PROVIDER_FAILOVER`.
- NZB segments are standard NZB 1.1; downloaders extract segment identity directly from article bytes. Readers MUST accept both canonical NZB namespaces, http://www.newzbin.com/DTD/2003/nzb and http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd, or match elements irrespective of namespace prefixing.
- NNTP headers, file subjects, and XML (file or segment) ordering carry no cryptographic meaning.

## Processing and Failure Rules

The downloader reads the NZB metadata before requesting an article. A compliant encrypted NZB MUST contain `<meta type="yenc_encrypted">true</meta>` and normally carries `<meta type="password">`. A password without the provenance marker remains an archive password and MUST NOT enable transport decryption. The article bootstrap in fetched article bytes is the only cryptographic identity input. Subjects, NNTP headers, post order, XML order, and `<segment bytes>` have no cryptographic meaning. `yenc_encrypted` matches `true` case-insensitively; the optional `yenc_version` must be `1.2` and the optional `yenc_cipher` must be `XChaCha20-Poly1305` (case-insensitive), both after trimming whitespace. Any other version or cipher value fails closed. There is no mode metadata. In an ARTICLE response the encrypted yEnc block starts after the blank line that ends the headers; it is never located by trial decryption.

A block is multipart if and only if physical line 2 after `=ybegin` is `=ypart`; otherwise it is single-part. For a single-part block, `=yencryption` is physical line 2, immediately after `=ybegin`. For a multipart block, `=ypart` is line 2 and `=yencryption` is line 3. Encrypted receivers NEVER read `part=` from `=ybegin` to decide header placement; they decrypt physical line 2 first. A mismatch between physical line 2 framing and restored `=ybegin` content is corrupt framing and MUST fail under `PROVIDER_FAILOVER`. Encrypted files MUST be strictly smaller than 2^32 bytes (four-GiB bound); producers refuse larger files and receivers treat begin or size values >= 2^32 as `PROVIDER_FAILOVER`. The canonical wire line is `=yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>`. Each placeholder is replaced by lowercase hexadecimal characters: salt is 32 hex chars, index is 8 hex chars (uint32_be in range 00000001..ffffffff), and tag is 32 hex chars, producing exactly 128 characters excluding CRLF. The line uses one ASCII space between its five tokens and has no leading or trailing whitespace. Parsers reject any other field order, spacing, field count, cipher name, character set, or value length.

When both standards are used, the raw salt and uint32_be segmentIndex prepended to Line 1 and the hexadecimal salt and index in `=yencryption` MUST represent the same values. Wire CRC values cover ciphertext and are checked before AEAD decryption. After authentication succeeds, decoders MUST NOT persist the ciphertext wire CRC into any verification path (PAR2, quick-check, whole-file CRC folding); they either clear the CRC metadata or recompute it over authenticated plaintext. Producers MUST dot-stuff per RFC 3977 Section 3.1.1 and consumers MUST dot-unstuff before line splitting and index counting; segment byte counts report dot-unstuffed content length. Each AEAD call uses the Body Standard Section 2.1 associated data, computed from the restored control lines only. Uploaders write `<segment bytes>` as the plaintext segment length, and downloaders MAY compare it as a consistency check.

Encrypted articles require a present, non-empty `name=` and an applicable ciphertext CRC (`pcrc32` for multipart, `crc32` for single-part). Missing or invalid values are `PROVIDER_FAILOVER`; unauthenticated output remains forbidden. A multipart `=yend` carries only `pcrc32`: producers MUST NOT emit a whole-file `crc32=` on any part of an encrypted multipart article (including the last), and receivers ignore one if present.

### Key Derivation Inputs (both standards)

The KDF inputs are fixed in both standards and are not configurable: the password is encoded to UTF-8 exactly as its source text with NO Unicode normalization (no NFC, NFD, NFKC, or NFKD); Argon2id uses version 0x13 (v=19), time=1, memory=65536 KiB, parallelism=4, and a 32-byte output, with empty optional secret and associated data. Passwords carried by `<meta type="password">` must be XML-representable: the XML-escaped content must parse back to the exact password used by the KDF. Parsers must not silently alter the KDF password (no stripping, trimming, case folding, normalization, or character dropping); producers must refuse XML-unrepresentable passwords on the NZB route, and consumers must treat a password that fails XML parsing as METADATA_VALIDATION.

Failures in NZB metadata or local configuration before article retrieval are structural. Missing provenance, malformed XML, no available password (neither in the NZB nor supplied to the client), or an unsupported `yenc_version`, `yenc_cipher`, or KDF parameter set is fatal and MUST NOT trigger provider failover. Failures in fetched article bytes after those checks pass are provider corruption. This includes malformed, missing, misplaced, or duplicate control lines; an unsupported cipher token in `=yencryption`; dual-salt or dual-index mismatch; failed control-line restoration; a fetched article in an unexpected mode (for example body-only framing at a combined-only receiver); wire CRC mismatch; a segmentIndex whose 4-byte big-endian representation contains bytes 0x0A or 0x0D; truncation; and AEAD authentication failure. Clients retry provider corruption on eligible alternate providers. Both tiers release zero plaintext and zero ciphertext as final output.

## Wire Specifications and Invariants

### Control Lines Encryption Specification

File: [`yEnc Control Lines Encryption Standard.txt`](./yEnc%20Control%20Lines%20Encryption%20Standard.txt)  
Algorithm: FF1 Format-Preserving Encryption

```
Target: yEnc control lines (lines beginning with "=y")
Alphabet: 253 bytes (0x01-0xFF excluding CR/LF: 0x0D and 0x0A)
Cipher: FF1 with AES-256
Key Derivation: Argon2id(password UTF-8 no-normalization, salt, time=1, memory=65536 KiB, parallelism=4, 32-byte output, version 0x13)
Tweak: HMAC-SHA256(masterKey, "yenc-control tweak" || uint32_be(segmentIndex) || uint32_be(lineIndex))[0:8]
segmentIndex: Explicit unsigned 32-bit integer in range 1..=4294967295 from article bootstrap
Salt: 16 random bytes sampled from 253-byte Alphabet, prepended to line 1 as part of 20-byte bootstrap prefix
Length: Line 1 expands by 20 bytes; lines 2..N preserve exact byte length
Line Counting: 1-based physical line numbers after dot-unstuffing
Restoration: deterministic, position-based; data lines are never decrypted
```

### Body Encryption Specification

File: [`yEnc Body Encryption Standard.txt`](./yEnc%20Body%20Encryption%20Standard.txt)  
Algorithm: XChaCha20-Poly1305 Authenticated Encryption

```
Target: Binary file data (before yEnc encoding)
Cipher: XChaCha20 (256-bit key, 192-bit nonce)
Authentication: Poly1305 (128-bit tag)
Key Derivation: Argon2id(password UTF-8 no-normalization, salt, time=1, memory=65536 KiB, parallelism=4, 32-byte output, version 0x13)
Nonce: HMAC-SHA256(key, "yenc-body nonce" || uint32_be(segmentIndex))[0:24]
AAD: "yenc-body aad" || uint32_be(partNumber) || uint32_be(partBegin) || uint64_be(segmentBytes) || uint32_be(nameLength) || name (Body Standard Section 2.1)
segmentIndex: Explicit unsigned 32-bit integer in range 1..=4294967295 from article bootstrap
Salt: 16 cryptographically secure random bytes (CSPRNG) drawn from the 253-byte Alphabet (no 0x00, 0x0A, or 0x0D)
Format: =yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>
Placement: Single-part line 2 (after =ybegin); multipart line 3 (after =ypart)
CRC Handling: Wire CRC in =yend covers ciphertext; verified then cleared (crc32 = None) or recomputed over authenticated plaintext
```

### Error Handling and Security Invariants

There are two error tiers:

1. Fatal structural failures (`METADATA_VALIDATION`) arise from NZB metadata or local configuration before article retrieval. Examples are missing provenance, malformed XML, no available password, or an unsupported `yenc_version` or `yenc_cipher` value. The client aborts the job without querying alternate providers.

2. Retriable provider corruption (`PROVIDER_FAILOVER`) arises from fetched article bytes after structural validation succeeds. Examples are malformed, missing, misplaced, or duplicate control lines; an unsupported cipher token in `=yencryption`; dual-salt or dual-index mismatch; failed control-line restoration; a fetched article in an unexpected mode (for example body-only framing at a combined-only receiver); wire CRC mismatch; truncation; and Poly1305 authentication failure. The client tries eligible alternate providers and applies normal repair policy if they all fail.

A client MUST NOT release or write unauthenticated plaintext or ciphertext to a target file, a cache visible to downstream stages, or a subsequent pipeline stage. It MAY retain one article in working memory until validation completes and MUST discard that working data on failure.

Because AEAD authentication must finish before plaintext release, an implementation MAY buffer one complete article. Working memory MUST remain O(article_size) and MUST NOT grow with a multipart file or release. Reference implementations accept typical article sizes from 128 KiB through 4 MiB and enforce local safety limits up to 8 MiB. Those values are implementation guidance, not wire limits. A receiver MAY reject an article above its configured limit before allocation or decryption.

## Status

Both specifications are published as experimental v1.2 wire contracts (v1.2 Experimental) dated 2026-10-10. Version 1.2 defines combined mode only (control line encryption and body encryption together); other framing modes are reserved for future standards. Decoders decrypt physical line 2 first to determine multipart framing; contradictory framing is rejected under `PROVIDER_FAILOVER`. Encrypted files MUST be strictly smaller than 2^32 bytes (four-GiB bound); producers refuse larger files and receivers treat begin or size values >= 2^32 as `PROVIDER_FAILOVER`. The two error tiers carry the identifiers used throughout this README and both standards: `METADATA_VALIDATION` for the fatal structural tier and `PROVIDER_FAILOVER` for the retriable provider-corruption tier. The shared salt is sampled uniformly from the 253-byte Alphabet (excluding 0x00, 0x0A, and 0x0D). Body encryption binds exact associated data (Section 2.1 of the Body Standard) covering each segment's assembly position and `=ybegin` name; v1.2 producers emit combined mode only. They form an interoperability baseline across Pesto, Penne, SABnzbd, NZBGet, Nyuu, and ngPost. The wire contracts for control-line encryption (FF1) and body encryption (XChaCha20-Poly1305) define self-describing article bootstraps, so NZB segments stay standard NZB 1.1.

## Tooling and Conformance Suite

### Scripts (`scripts/`)

The repository provides automated validation and reference implementations under `scripts/`:

- `yenc_enc_reference.py`: Canonical reference implementation of cryptographic derivations (Argon2id KDF, HMAC-SHA256 nonces and tweaks, NIST SP 800-38G FF1 with Radix 253 Alphabet, and XChaCha20-Poly1305 AEAD).
- `generate_conformance_vectors.py`: Deterministic test vector generator producing JSON fixtures with cryptographic inputs, wire lines, and expected outcomes.
- `test_conformance_vectors.py`: Automated test harness exercising all generated test vector fixtures and validating failure-mode enforcement.
- `test_standards_v1.py`: Specification consistency and grammar validator ensuring normative texts agree on constants, layout, and error models.

Run tests using pytest or direct invocation:
```bash
pip install -r scripts/requirements.txt
pytest scripts/
```

### Test Vectors (`test-vectors/`)

Deterministic test vectors are maintained under `test-vectors/` along with `manifest.json` carrying SHA-256 integrity digests:

- `argon2id.json`: Key derivation test vectors including exact byte handling with no Unicode normalization.
- `nonce_tweak.json`: HMAC-SHA256 19-byte body nonce and 26-byte control tweak derivation vectors.
- `body_encryption.json`: XChaCha20-Poly1305 AEAD round-trips with Section 2.1 Associated Data.
- `control_line_encryption.json`: NIST SP 800-38G FF1 control-line encryption round-trips and deterministic multi-line article layout fixtures.
- `malformed_inputs.json`: Malformed headers, bad salts, corrupted tags, framing mismatches, and zero-output assertions.
- `nzb_segment_identity.json`: Standard NZB 1.1 XML parsing, segmentIndex binding, and metadata mutation rejections.
- `index_allocation.json`: Uploader segmentIndex sequence progression skipping indices containing forbidden delimiter bytes (0x0A, 0x0D).

To regenerate vectors deterministically:
```bash
python3 scripts/generate_conformance_vectors.py test-vectors
```

## Contributing

For questions, implementation discussion, or conceptual feedback, use [Discussions](../../discussions). To report an error or propose an improvement, [open an issue](../../issues/new) with the motivation and rationale. Specification changes go through [pull requests](../../pulls) that describe the motivation and impact, keep both standards consistent, note backward compatibility implications, and state which standard(s) are affected.

## Related Work

- [NIST SP 800-38G](https://csrc.nist.gov/publications/detail/sp-800-38g/final): FF1 and FF3 Format-Preserving Encryption specification
- [RFC 8439](https://tools.ietf.org/html/rfc8439): ChaCha20 and Poly1305 for AEAD (XChaCha20-Poly1305 extension)
- [yEnc specification](http://www.yenc.org/yenc-draft.1.3.txt): Original yEnc encoding format
- [Argon2](https://tools.ietf.org/html/rfc9106): Password-based key derivation function (RFC 9106)

## License

This specification is released under the MIT License. See [LICENSE](LICENSE) for details.

---

**Maintainer**: [@Tensai75](https://github.com/Tensai75)  
**Repository**: [github.com/Tensai75/yenc-encryption-standards](https://github.com/Tensai75/yenc-encryption-standards)
