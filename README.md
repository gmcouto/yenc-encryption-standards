# yEnc Encryption Standards

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Experimental Wire Contract (v1.1)](https://img.shields.io/badge/Status-v1.1%20Experimental-blue.svg)]()

This repository contains specifications for **two complementary encryption standards** designed specifically for yEnc-encoded binary blocks used in Usenet transfers. Both standards can be used individually or combined depending on security and obfuscation requirements.

## Standards Overview

### 1. yEnc Control Lines Encryption Standard

**Purpose**: Obfuscation and metadata protection  
**Target**: yEnc header and footer lines (lines beginning with "=y")  
**Method**: FF1 Format-Preserving Encryption

- **Format-preserving**: Encrypted control lines maintain exact length (lines 2..N) and character compatibility; the first control line (lineIndex=1) expands by 20 bytes due to the prepended article bootstrap (16-byte raw salt from the 253-byte Alphabet and 4-byte big-endian uint32 segmentIndex).
- **Selective encryption**: Only metadata is encrypted, binary data lines remain completely untouched.
- **Total obfuscation**: Hides file names, sizes, part information, and yEnc structure.
- **Line counting**: 1-based physical line numbers after NNTP dot-unstuffing.
- **Optional**: Can be omitted when obfuscation is not required.

### 2. yEnc Body Encryption Standard

**Purpose**: Content protection with authentication  
**Target**: Binary file data before yEnc encoding  
**Method**: XChaCha20-Poly1305 Authenticated Encryption

- **Content security**: Encrypts actual file data with strong authentication.
- **Integrity protection**: Detects tampering through cryptographic authentication; failed authentication results in complete decryption failure with zero partial data output.
- **Transparent**: Standard yEnc parsers process encrypted blocks normally.
- **Canonical format**: Uses a strict five-token control line `=yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>` in lowercase hex (128 characters).
- **Placement**: Physical line 2 for single-part articles (immediately after `=ybegin`), physical line 3 for multipart articles (immediately after `=ypart`).
- **Wire CRC normalization**: Wire CRC covers ciphertext and is cleared after AEAD verification so downstream consumers verify plaintext CRC.
- **Optional**: Can be omitted if cryptographic protection of file content is not required.

## Usage Scenarios

### Scenario 1: Content Protection Only

- **Use**: Body Encryption Standard only.
- **When**: Need strong file protection while control metadata remains visible.
- **Benefits**: Strong authenticated encryption, standard yEnc compatibility.

### Scenario 2: Obfuscation Only

- **Use**: Control Lines Encryption Standard only.
- **When**: Need to hide upload metadata while file content protection is handled separately or not required.
- **Benefits**: Complete metadata obfuscation, format-preserving compatibility.

### Scenario 3: Maximum Security (Combined Mode)

- **Use**: Both standards combined.
- **When**: Need complete protection of both content and metadata.
- **Dual-Bootstrap Agreement**: The 16-byte raw salt and 4-byte big-endian segmentIndex from Line 1 MUST equal the 16-byte salt and 8-hex index carried in `=yencryption` byte-for-byte and value-for-value.
- **Benefits**: Authenticated file encryption and total metadata obfuscation under a single unified password.

### Scenario 4: Standard Upload

- **Use**: Neither standard.
- **When**: No special security requirements.
- **Benefits**: Standard yEnc processing, maximum compatibility.

## Password Management and Canonical NZB Metadata

### Transport Provenance vs Archive Passwords

To distinguish encrypted yEnc transport from unencrypted uploads carrying archive passwords (such as password-protected RAR or 7z files), compliant NZB documents carry explicit metadata flags:

1. **Encrypted Transport**: When yEnc encryption is present, the NZB `<head>` MUST contain `<meta type="yenc_encrypted">true</meta>`. The download client reads the password from `<meta type="password">` to decrypt the yEnc transport stream.
2. **Archive Password Decoupling**: If an NZB contains `<meta type="password">` without `<meta type="yenc_encrypted">true</meta>`, the password applies solely to downstream extraction tools. The download client MUST process segments as standard unencrypted yEnc blocks without attempting transport decryption.

### NZB 1.1 Clean Segment Example (Encrypted Release)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!-- <!link http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd> -->
<!-- <newzbin dtd> -->
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

- `number`: Standard NZB 1.1 1-based part number within the file.
- `segmentIndex`: Explicit unsigned 32-bit integer in range `1..=4294967295` encoded in article bootstrap bytes (Line 1 prefix and =yencryption index parameter).
- Formatting: 4-byte big-endian integer on Line 1; 8-character lowercase hexadecimal string in =yencryption.
- Uniqueness: Globally unique across the entire upload session.
- Decoupling: NZB segment tags contain no custom XML attributes; downloaders extract segment identity directly from article bytes.
- Decoupling of Presentation Metadata: NNTP headers, file subjects, and XML (file or segment) ordering carry no cryptographic meaning.

## Processing and Failure Rules

The downloader reads the NZB metadata before requesting an article. A compliant encrypted NZB MUST contain both `<meta type="password">` and `<meta type="yenc_encrypted">true</meta>`. A password without the provenance marker remains an archive password and MUST NOT enable transport decryption. The article bootstrap in fetched article bytes is the only cryptographic identity input. Subjects, NNTP headers, post order, and XML order have no cryptographic meaning.

For a single-part block, `=yencryption` is physical line 2, immediately after `=ybegin`. For a multipart block, `=ypart` remains line 2 and `=yencryption` is line 3. The canonical wire line is `=yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>`. Each placeholder is replaced by lowercase hexadecimal characters: salt is 32 hex chars, index is 8 hex chars (uint32_be in range 00000001..ffffffff), and tag is 32 hex chars, producing exactly 128 characters excluding CRLF. The line uses one ASCII space between its five tokens and has no leading or trailing whitespace. Parsers reject any other field order, spacing, field count, cipher name, character set, or value length.

When both standards are used, the raw salt and uint32_be segmentIndex prepended to Line 1 and the hexadecimal salt and index in `=yencryption` MUST represent the same values. Wire CRC values cover ciphertext and are checked before AEAD decryption. After authentication succeeds, decoders clear those CRC values before handing plaintext to assembly or PAR2.

Failures in NZB metadata or local configuration before article retrieval are structural. Missing provenance, malformed XML, a missing password, or a locally unsupported encryption mode is fatal and MUST NOT trigger provider failover. Failures in fetched article bytes after those checks pass are provider corruption. This includes malformed, missing, misplaced, or duplicate control lines; an unsupported cipher token in `=yencryption`; dual-salt or dual-index mismatch; CRC mismatch; truncation; and AEAD authentication failure. Clients retry provider corruption on eligible alternate providers. Both tiers release zero plaintext and zero ciphertext as final output.

## Wire Specifications and Invariants

### Control Lines Encryption Specification
**File**: [`yEnc Control Lines Encryption Standard.txt`](./yEnc%20Control%20Lines%20Encryption%20Standard.txt)  
**Algorithm**: FF1 Format-Preserving Encryption  

```
Target: yEnc control lines (lines beginning with "=y")
Alphabet: 253 bytes (0x01-0xFF excluding CR/LF: 0x0D and 0x0A)
Cipher: FF1 with AES-256
Key Derivation: Argon2id(password, salt, time=1, memory=64MB, threads=4, 256-bit output)
Tweak: HMAC-SHA256(master, "yenc-control tweak" || uint32_be(segmentIndex) || uint32_be(lineIndex))[0:8]
segmentIndex: Explicit unsigned 32-bit integer in range 1..=4294967295 from article bootstrap
Salt: 16 random bytes sampled from 253-byte Alphabet, prepended to line 1 as part of 20-byte bootstrap prefix
Length: Line 1 expands by 20 bytes; lines 2..N preserve exact byte length
Line Counting: 1-based physical line numbers after dot-unstuffing
```

### Body Encryption Specification

**File**: [`yEnc Body Encryption Standard.txt`](./yEnc%20Body%20Encryption%20Standard.txt)  
**Algorithm**: XChaCha20-Poly1305 Authenticated Encryption  

```
Target: Binary file data (before yEnc encoding)
Cipher: XChaCha20 (256-bit key, 192-bit nonce)
Authentication: Poly1305 (128-bit tag)
Key Derivation: Argon2id(password, salt, time=1, memory=64MB, threads=4, 256-bit output)
Nonce: HMAC-SHA256(key, "yenc-body nonce" || uint32_be(segmentIndex))[0:24]
segmentIndex: Explicit unsigned 32-bit integer in range 1..=4294967295 from article bootstrap
Salt: 16 cryptographically secure random bytes (CSPRNG)
Format: =yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> index=<8_hex_chars> tag=<32_hex_chars>
Placement: Single-part line 2 (after =ybegin); multipart line 3 (after =ypart)
CRC Handling: Wire CRC in =yend covers ciphertext; verified then cleared (crc32=None)
```

### Error Handling and Security Invariants

### Two-tier error model

1. Fatal structural failures (`METADATA_VALIDATION`) arise from NZB metadata or local configuration before article retrieval. Examples are missing provenance, malformed XML, a missing password, or a locally unsupported encryption mode. The client aborts the job without querying alternate providers.

2. Retriable provider corruption (`PROVIDER_FAILOVER`) arises from fetched article bytes after structural validation succeeds. Examples are malformed, missing, misplaced, or duplicate control lines; an unsupported cipher token in `=yencryption`; dual-salt or dual-index mismatch; failed control-line restoration; wire CRC mismatch; truncation; and Poly1305 authentication failure. The client tries eligible alternate providers and applies normal repair policy if they all fail.

### Zero-output guarantee

A client MUST NOT release or write unauthenticated plaintext or ciphertext to a target file, a cache visible to downstream stages, or a subsequent pipeline stage. It MAY retain one article in working memory until validation completes and MUST discard that working data on failure.

### Bounded memory processing

An implementation MAY buffer one complete article because AEAD authentication must finish before plaintext release. Working memory MUST remain O(article_size) and MUST NOT grow with a multipart file or release. Reference implementations accept typical article sizes from 128 KiB through 4 MiB and enforce local safety limits up to 8 MiB. Those values are implementation guidance, not wire limits. A receiver MAY reject an article above its configured limit before allocation or decryption.

## Status

Both specifications are published as **experimental v1.1 wire contracts (v1.1 Experimental)** dated 2026-10-01, establishing an immutable interoperability baseline across Pesto, Penne, SABnzbd, NZBGet, Nyuu, and ngPost. The wire contracts for control-line encryption (FF1) and body encryption (XChaCha20-Poly1305) define self-describing article bootstraps and clean NZB 1.1 decoupling.

## Contributing

We welcome contributions to improve and refine the yEnc encryption standards:

### Discussions

For general questions, implementation discussions, or conceptual feedback, please use the [**Discussions**](../../discussions) section.

### Issues and Change Requests

- **Bug reports**: Found an error in the specification? Please [open an issue](../../issues/new).
- **Enhancement proposals**: Suggestions for improvements should be submitted as [issues](../../issues/new) with detailed rationale.
- **Specification changes**: Proposed modifications to the standard should be submitted as [pull requests](../../pulls) with clear justification and impact analysis.

### Pull Requests

When submitting PRs for specification changes:

1. Clearly describe the motivation and impact.
2. Update relevant sections consistently across both standards.
3. Consider backward compatibility implications.
4. Include example scenarios if applicable.
5. Specify which standard(s) are affected by the changes.

## Related Work

- [NIST SP 800-38G](https://csrc.nist.gov/publications/detail/sp-800-38g/final): FF1; and FF3 Format-Preserving Encryption specification
- [RFC 8439](https://tools.ietf.org/html/rfc8439): ChaCha20 and Poly1305 for AEAD (XChaCha20-Poly1305 extension)
- [yEnc specification](http://www.yenc.org/yenc-draft.1.3.txt): Original yEnc encoding format
- [Argon2](https://tools.ietf.org/html/rfc9106): Password-based key derivation function (RFC 9106)

## License

This specification is released under the MIT License. See [LICENSE](LICENSE) for details.

---

**Maintainer**: [@Tensai75](https://github.com/Tensai75)  
**Repository**: [github.com/Tensai75/yenc-encryption-standards](https://github.com/Tensai75/yenc-encryption-standards)
