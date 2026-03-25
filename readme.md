# Temporal Password Standard
Version: 2.1  
Date: March 24, 2026

## 1. Scope
This standard defines a dual-component memorized secret called a temporal password:
- Ordered text groups
- Ordered numeric intervals (`0..99`)

The two components are cryptographically bound into one canonical combined secret and verified with one password hash.

## 2. Secret Structure
- Group count `M` must satisfy `8 <= M <= 64`.
- Text groups are non-empty strings.
- Interval list length must equal text group length.
- Each interval is an integer in `[0, 99]`.

## 3. Canonical Combined Secret (Required)
The verifier input MUST be a deterministic, unambiguous encoding of both components.

Reference encoding:
- Group encoding: length-prefixed (`len:text` concatenation)
- Interval encoding: colon-separated values
- Final format:

`g:{M}|{encoded_groups}|t:{M}|{encoded_intervals}`

Example:
`g:3|2:ab1:Z3:cat|t:3|12:0:99`

## 4. Storage and Verification
- Store one verifier only: `combined_secret_hash`.
- Hash using a slow password KDF (Argon2id in production).
- Apply a server-side pepper from secret management (not from the user DB).
- Authenticate by recomputing the canonical combined secret and verifying it against the stored hash.

Prohibited:
- Separate stored hashes for text and interval components.
- Plaintext or reversible storage of either component.

## 5. Temporal Online Challenge Flow (Required)
To preserve temporal semantics and improve online resistance, login uses a challenge flow:

1. `POST /temporal/challenge/start`
- Input: username
- Output: `challenge_id`, expiry, constraints

2. `POST /temporal/challenge/submit`
- Input: `challenge_id`, one `{text, time}` pair, optional `finalize`
- Server stores incremental progress in short-lived cache.
- Server enforces timing between submissions:
  - Required elapsed time before next submit is based on the previous submitted interval.
  - Policy: `expected_wait = previous_interval * INTERVAL_UNIT_SECONDS`
  - Accepts configurable tolerance.
- If submitted too early, return `429 temporal_too_fast`.

3. Finalize
- Finalize requires at least 8 groups.
- On finalize, server runs full combined-secret verification.
- Generic failure responses are required.

Note: This timing control is implemented as non-blocking policy checks, not server `sleep()` delays.

## 6. Account Security Requirements
- IP rate limits on challenge start and submit endpoints.
- Account lockout after repeated failed final verifications.
- Generic credential failure responses.
- Audit logging for failed and successful authentication events.

## 7. Lifecycle Rules
- Enrollment creates a full new paired secret (both components).
- Rotation replaces the full paired secret as one unit.
- Recovery invalidates old verifier and requires full re-enrollment of both components.

## 8. Security Notes
- Temporal timing checks primarily strengthen online attack cost/control.
- Offline resistance comes from combined-secret hashing, Argon2id cost, salts, and pepper protection.
- This remains a single-factor memorized secret (knowledge factor), not MFA.
