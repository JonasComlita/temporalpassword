# Proposal: Dual-Component Paired-Secret Authentication Standard (Combined-Secret Model)
Version: 2.0  
Date: March 24, 2026  
Author(s): [Your Name/Organization]

## Abstract
This document defines a memorized-secret authentication standard where users provide two ordered components in one login event:

1. Text password groups (primary component)
2. Paired numeric codes (secondary component)

Unlike split-hash designs, this standard requires a **single canonical combined secret** to be derived from both components and hashed once with a slow, memory-hard algorithm (recommended: Argon2id), plus a server-side pepper stored outside the credential database (KMS/HSM/secret manager). Authentication succeeds only if the combined secret verifies.

This architecture prevents independent offline verification of each component after database compromise and forces brute-force attempts to target the full combined secret space.

## 1. Problem Statement and Rationale
Single-string passwords remain vulnerable to weak user choices, reuse, and offline cracking after database theft. Split-hash dual-secret approaches improve structure but still expose independent verification oracles for each component.

This standard keeps the two-component UX while binding both components into a single cryptographic verifier, increasing attacker workload in offline scenarios compared to independent component hashes.

## 2. Core Concepts
- `Password Group`: A non-empty text segment entered by the user.
- `Numeric Code`: A paired integer (0-99) linked by position to a password group.
- `Dual-Component Secret`: Two ordered lists of equal length: password groups and numeric codes.
- `Canonical Combined Secret`: A deterministic, unambiguous serialization of both ordered lists used as the sole KDF input.

## 3. Technical Specification
### 3.1 Data Structure and Constraints
- Password groups: ordered list length `M`, where `8 <= M <= 64`
- Numeric codes: ordered list length `M`, where each code is an integer `0..99`
- Both lists must have identical length and preserve order

### 3.2 Canonical Encoding
Implementations MUST serialize to one unambiguous string before hashing.

Recommended format:
- Text groups: length-prefixed encoding for each group
- Numeric list: delimiter-separated or fixed-width encoding
- Include section labels and list length

Example canonical template:
`g:{M}|{encoded_groups}|t:{M}|{encoded_codes}`

Where:
- `encoded_groups` might be `len:text` repeated (e.g., `2:ab1:c`)
- `encoded_codes` might be `12:08:05:99`

### 3.3 Secure Storage
The verifier MUST be produced from the canonical combined secret only.

Required:
1. Derive canonical combined secret from submitted components.
2. Prepend/derive pepper material (server-side secret, not in DB).
3. Hash using Argon2id with tuned memory/time/parallelism settings.
4. Store a single hash verifier string (including algorithm params/salt as supported by the hasher).

Prohibited:
- Storing plaintext components
- Reversible encryption as primary verifier
- Storing independent hash verifiers for primary and secondary components

### 3.4 Verification Protocol
1. Client sends both ordered components in one authentication request.
2. Server reconstructs canonical combined secret.
3. Server verifies against stored single combined verifier using constant-time comparison path from the password hasher.
4. Return generic failure on mismatch.

## 4. Security Analysis
### 4.1 Offline Attack Model
With a single combined verifier, the attacker has only one oracle:
- `is_combined_secret_correct(primary, secondary)?`

They cannot independently test primary or secondary components in isolation from the credential DB alone.

### 4.2 Numeric Component Entropy
For `M` groups and codes in `0..99`, numeric combinations are:
- `100^M`

Examples:
- `M=8`: `100^8 = 10^16` (about 53 bits)
- `M=12`: `100^12 = 10^24` (about 80 bits)

Total resistance is determined by combined-secret entropy, user choice quality, and KDF cost settings.

### 4.3 Pepper Benefits
If DB is stolen but pepper remains protected in KMS/HSM/secret manager, attackers cannot directly validate guesses from DB contents alone. Pepper compromise collapses this benefit, so key management and rotation policy are critical.

### 4.4 Online Attack Mitigations (Required)
- IP and account rate limiting
- Progressive lockouts or cooldowns
- Generic error responses
- Auditing and anomaly detection

## 5. Usability and Client UX
The UI should guide users through group/code pairs step-by-step while preserving order. The backend remains stateless and verifies only on complete submission.

Usability hypothesis: pair-based secrets may be easier for some users to memorize than a single highly complex random string of equivalent entropy. This should be validated with user testing.

## 6. Identity Lifecycle
- Enrollment: user sets both components together.
- Rotation: user replaces full dual-component secret as one unit.
- Recovery: reset invalidates the old verifier and requires creation of a full new dual-component secret.

## 7. Relationship to NIST SP 800-63B
This is still a single-factor memorized secret (`something you know`), not MFA. It is a structured memorized-secret scheme intended to improve offline resistance versus naive single-string and split-hash paired-secret designs.

## 8. Minimum Compliance Checklist
- Single combined verifier per account for temporal auth
- Canonical encoding is deterministic and unambiguous
- Argon2id in production
- Server-side pepper from external secret management
- Rate limiting and lockout controls enabled
- Generic auth error responses
- Full-credential reset and rotation flow
