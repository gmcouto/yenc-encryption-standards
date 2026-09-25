# yEnc Encryption Standards

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Frozen Wire Contract (v1.0)](https://img.shields.io/badge/Status-v1.0%20Frozen-blue.svg)]()

This repository contains specifications for **two complementary encryption standards** designed specifically for yEnc-encoded binary blocks used in Usenet transfers. Both standards can be used individually or combined depending on security and obfuscation requirements.

## Standards Overview

### 1. yEnc Control Lines Encryption Standard

**Purpose**: Obfuscation and metadata protection  
**Target**: yEnc header and footer lines (lines beginning with "=y")  
**Method**: FF1 Format-Preserving Encryption

- **Format-preserving**: Encrypted control lines maintain exact length (lines 2..N) and character compatibility; the first control line (lineIndex=1) expands by 16 bytes due to prepended random salt from the 253-byte Alphabet
- **Selective encryption**: Only metadata is encrypted, binary data lines remain completely untouched
- **Total obfuscation**: Hides file names, sizes, part information, and yEnc structure
- **Optional**: Can be omitted when obfuscation is not required

### 2. yEnc Body Encryption Standard

**Purpose**: Content protection with authentication  
**Target**: Binary file data before yEnc encoding  
**Method**: XChaCha20-Poly1305 Authenticated Encryption

- **Content security**: Encrypts actual file data with strong authentication
- **Integrity protection**: Detects tampering through cryptographic authentication; failed authentication results in complete decryption failure with zero partial data output
- **Transparent**: Standard yEnc parsers process encrypted blocks normally
- **Canonical format**: Uses single-line `=yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> tag=<32_hex_chars>` control line
- **Optional**: Can be omitted if cryptographic protection of file content is not required

## Usage Scenarios

### Scenario 1: Content Protection Only

- **Use**: Body Encryption Standard only
- **When**: Need strong file protection but metadata can remain visible
- **Benefits**: Strong authenticated encryption, standard yEnc compatibility

### Scenario 2: Obfuscation

- **Use**: Control Lines Encryption Standard only
- **When**: Need to hide upload metadata but file content protection handled separately or not required
- **Benefits**: Complete metadata obfuscation, format-preserving compatibility

### Scenario 3: Maximum Security

- **Use**: Both standards combined
- **When**: Need complete protection of both content and metadata
- **Benefits**: Authenticated file encryption + total metadata obfuscation

### Scenario 4: Standard Upload

- **Use**: Neither standard
- **When**: No special security requirements
- **Benefits**: Standard yEnc processing, maximum compatibility

## Password Management and NZB Metadata

**NZB File Storage**: When encryption is used, the password CAN be stored in the NZB file using the standard password meta tag:

```xml
<meta type="password">your_encryption_password</meta>
```

**NZB 1.1 Segment Extension Example**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nzb PUBLIC "-//newzBin//DTD NZB 1.1//EN"
 "http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd">
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <head>
    <meta type="password">correct horse battery staple</meta>
  </head>
  <file poster="poster@example.com"
        date="1727280000"
        subject="4Qd7sJm2pL yEnc (1/2)">
    <groups>
      <group>alt.binaries.example</group>
    </groups>
    <segments>
      <segment bytes="750000" number="1" segmentIndex="1">article-1@example.com</segment>
      <segment bytes="750000" number="2" segmentIndex="2">article-2@example.com</segment>
    </segments>
  </file>
  <file poster="poster@example.com"
        date="1727280001"
        subject="n8Vx3KaP yEnc (1/1)">
    <groups>
      <group>alt.binaries.example</group>
    </groups>
    <segments>
      <segment bytes="500000" number="1" segmentIndex="3">article-3@example.com</segment>
    </segments>
  </file>
</nzb>
```

The attributes have distinct meanings:
- `number` is the standard NZB 1.1 1-based part number within the file.
- `segmentIndex` is the explicit global index (range 1..=4294967295) used for encryption derivation.

**Download Client Behavior**: Download clients MUST use the password from the NZB meta tag (if available) for automatic decryption of encrypted yEnc blocks.

**Combined Encryption**: When using both encryption standards together (Scenario 3), the **same password MUST be used** for both control lines and body encryption. This approach is:

- **Cryptographically secure**: Different domain separation strings ensure independent key derivation
- **User-friendly**: Single password management instead of tracking multiple passwords
- **Implementation-friendly**: Simplified NZB handling and software configuration

**External Preprocessing**: If external encryption was used in preprocessing (e.g., password-protected RAR files), the **same password MUST be used** for yEnc block encryption to avoid multiple passwords in the NZB file and maintain single-password simplicity for end users.

This unified password approach provides maximum security with optimal usability and implementation simplicity.

## Body Encryption vs. Preprocessing Methods

The **Body Encryption Standard** is designed to replace traditional preprocessing encryption methods such as password-protected RAR archives. On-the-fly body encryption offers significant advantages over preprocessing approaches:

### Efficiency Benefits

**Storage Requirements**:

- **No temporary files**: Encryption happens during upload, eliminating need for encrypted intermediate files
- **50% storage reduction**: Avoids storing both original and encrypted versions simultaneously
- **Streaming processing**: Files can be encrypted and uploaded directly from source without disk buffering

**Performance Advantages**:

- **Streamlined processing**: Single-pass encryption without intermediate archive creation
- **Efficient algorithm**: ChaCha20 is optimized for software implementation and runs efficiently on modern CPUs
- **Reduced I/O operations**: Eliminates read/write cycles for temporary encrypted files
- **Memory efficiency**: Streaming encryption uses constant memory regardless of file size

**Operational Benefits**:

- **Simplified workflow**: Single-step encryption+upload instead of encrypt-then-upload process
- **Reduced complexity**: No need to manage temporary encrypted archives or cleanup processes
- **Better error handling**: Immediate feedback on encryption/upload failures without orphaned temp files
- **Atomic operations**: Upload and encryption success/failure are coupled together

### Traditional Preprocessing Limitations

**RAR/ZIP Password Protection**:

- Requires full file compression before upload
- Creates temporary encrypted archives consuming additional disk space
- Slower compression algorithms with higher CPU overhead
- Two-stage process prone to interruption and cleanup issues
- Limited to compression tool's encryption capabilities

**On-the-fly Body Encryption**:

- Direct encryption during yEnc encoding process
- No intermediate file creation or storage overhead
- Modern authenticated encryption with stronger security guarantees
- Integrated error handling and recovery mechanisms
- Cryptographically superior to legacy archive encryption methods

## Specifications

### Control Lines Encryption Standard

**File**: [`yEnc Control Lines Encryption Standard.txt`](./yEnc%20Control%20Lines%20Encryption%20Standard.txt)

**Algorithm**: FF1 Format-Preserving Encryption

```
Target: yEnc control lines (lines beginning with "=y")
Alphabet: 253 bytes (0x01-0xFF excluding CR/LF)
Cipher: FF1 with AES-256
Key Derivation: Argon2id(password, salt, time=1, memory=64MB, threads=4, 256-bit output)
Tweak: HMAC-SHA256(master, "yenc-control tweak" || uint32_be(segmentIndex) || uint32_be(lineIndex))[0:8]
segmentIndex: Explicit unsigned 32-bit integer in range 1..=4294967295 from NZB segment attribute
Salt: 16 random bytes sampled from 253-byte Alphabet, prepended to line 1 (lineIndex=1 expands by 16B, lines 2..N preserve length)
```

### Body Encryption Standard

**File**: [`yEnc Body Encryption Standard.txt`](./yEnc%20Body%20Encryption%20Standard.txt)

**Algorithm**: XChaCha20-Poly1305 Authenticated Encryption

```
Target: Binary file data (before yEnc encoding)
Cipher: XChaCha20 (256-bit key, 192-bit nonce)
Authentication: Poly1305 (128-bit tag)
Key Derivation: Argon2id(password, salt, time=1, memory=64MB, threads=4, 256-bit output)
Nonce: HMAC-SHA256(key, "yenc-body nonce" || uint32_be(segmentIndex))[0:24]
segmentIndex: Explicit unsigned 32-bit integer in range 1..=4294967295 from NZB segment attribute
Salt: 16 cryptographically secure random bytes (CSPRNG), carried in =yencryption control line
Format: =yencryption cipher=XChaCha20-Poly1305 salt=<32_hex_chars> tag=<32_hex_chars>
```

## Security Properties

### Control Lines Encryption

- **Confidentiality**: AES-256 equivalent security for metadata
- **Format-preserving**: No information leakage through format changes
- **Deterministic**: Consistent output for identical inputs
- **Obfuscation**: Complete hiding of yEnc structure and metadata
- **Note**: Provides confidentiality only, not integrity verification

### Body Encryption

- **Confidentiality**: XChaCha20 encryption of file content
- **Authenticity**: Poly1305 authentication prevents tampering
- **Integrity**: Cryptographic verification of data integrity
- **Non-malleability**: Authentication tag prevents modification attacks
- **Note**: Provides both confidentiality and integrity protection

### Combined Usage

- **Total protection**: Both content and metadata encrypted
- **Defense in depth**: Multiple encryption layers with different algorithms
- **Flexible deployment**: Can be applied independently or together

## Implementation Considerations

### Control Lines Encryption

- Requires FF1-compatible library supporting custom alphabets
- First line of article body must be inspected prior to yEnc parsing in order to detect and decrypt encrypted control lines
- No backward compatibility: existing download tools and yEnc parsers will not recognize encrypted control lines

### Body Encryption

- Requires XChaCha20-Poly1305 implementation (widely available)
- Authentication tag stored in `=yencryption` control line
- Standard yEnc tools can process encrypted blocks normally
- Failed authentication must abort decryption completely

### Both Standards

- Each NZB `<segment>` MUST carry an explicit `segmentIndex="N"` attribute (range 1..=4294967295)
- Segment indexing must be globally unique across the upload session
- NNTP headers, file subjects, and file ordering have no cryptographic meaning
- Password can be stored in NZB meta tags for automatic decryption

## Status

Both specifications are published as **frozen v1.0 wire contracts (v1.0 Frozen)**, establishing a permanent, immutable interoperability baseline across Pesto, Penne, SABnzbd, and NZBGet. The wire contracts for control-line encryption (FF1) and body encryption (XChaCha20-Poly1305) are finalized and frozen for implementation across all client engines.

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

1. Clearly describe the motivation and impact
2. Update relevant sections consistently across both standards
3. Consider backward compatibility implications
4. Include example scenarios if applicable
5. Specify which standard(s) are affected by the changes

## Related Work

- [NIST SP 800-38G](https://csrc.nist.gov/publications/detail/sp/800-38g/final): FF1 and FF3 Format-Preserving Encryption specification
- [RFC 8439](https://tools.ietf.org/html/rfc8439): ChaCha20 and Poly1305 for AEAD (XChaCha20-Poly1305 extension)
- [yEnc specification](http://www.yenc.org/yenc-draft.1.3.txt): Original yEnc encoding format
- [Argon2](https://tools.ietf.org/html/rfc9106): Password-based key derivation function

## License

This specification is released under the MIT License. See [LICENSE](LICENSE) for details.

---

**Maintainer**: [@Tensai75](https://github.com/Tensai75)  
**Repository**: [github.com/Tensai75/yenc-encryption-standards](https://github.com/Tensai75/yenc-encryption-standards)
