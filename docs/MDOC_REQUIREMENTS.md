To run e2e test, run:
```
cargo test --release --test e2e_balance_proof e2e_balance_proof -- --nocapture
```

# Requirements for Creation of mdoc (ZK-Compatible)

This document specifies the requirements for creating an mdoc that is compatible with the **mdoc_zk** circuits (Longfellow ZK proof over ISO/IEC 18013-5 mdoc). It is derived from the e2e balance proof investigation and the circuit interface.

References:
- ISO/IEC 18013-5 (Personal identification — mDL application)
- [Circuit interface](src/mdoc_zk/circuit_interface.md)
- E2E test: `tests/e2e_balance_proof.rs`

---

## 1. Ciphersuite and Cryptography

| Requirement | Detail |
|-------------|--------|
| **Issuer and device signatures** | ES256 only (COSE algorithm -7). P-256 curve. |
| **Digest algorithm** | SHA-256 only (no SHA-384 or SHA-512). |
| **Issuer auth** | COSE_Sign1 with protected header `{ 1: -7 }` (3 bytes when CBOR-encoded). |

The circuit assumes a fixed 18-byte prefix of the credential hash message (Sig_structure: array, "Signature1", protected ES256, empty AAD, then payload byte-string header). The protected header must encode to exactly 3 bytes so this prefix is correct.

---

## 2. Mobile Security Object (MSO)

### 2.1 Top-level keys and order

The MSO **must** be a CBOR map with the following keys in this **exact order**:

1. **version** — Text, value `"1.0"`.
2. **digestAlgorithm** — Text, value `"SHA-256"`.
3. **valueDigests** — Map (see below).
4. **deviceKeyInfo** — Map (see below).
5. **validityInfo** — Map (see below).

If `version` and `digestAlgorithm` are omitted or the key order differs, the circuit’s expectations on the MSO layout will not match and proof generation will fail (in-circuit assertion in the hash circuit).

### 2.2 valueDigests

- Structure: map from **namespace** (text) → map from **digestID** (unsigned int) → **digest** (byte string, 32 bytes).
- Each digest must be `SHA256(EncodedCbor(IssuerSignedItemBytes))`, i.e. SHA-256 of the tag-24 encoding of the raw IssuerSignedItem CBOR bytes for that attribute.
- digestID is typically `0` for the first attribute in a namespace.

### 2.3 deviceKeyInfo

- Must contain the **deviceKey** attribute first (COSE_Key map).
- Device key: EC2 (kty 2), P-256 (crv 1), with x and y as 32-byte byte strings (COSE labels -2, -3).
- Encoding must match what the circuit expects (uncompressed point coordinates).

### 2.4 validityInfo

- Map with **validFrom** and **validUntil**.
- Each value: CBOR **tag 0** (date/time) with **text** payload.
- Text must be **RFC 3339** format, **exactly 20 characters** (e.g. `2024-01-01T00:00:00Z`).

---

## 3. Issuer payload (issuerAuth payload)

- The issuer COSE_Sign1 **payload** must be the **tag-24 (EncodedCbor) encoding** of the MSO bytes.
- That is: CBOR tag 24 followed by a byte string whose content is the raw MSO map bytes.
- Encoding: `0xd8 0x18` (tag 24), then byte string (e.g. `0x58` + length + MSO bytes for length &lt; 256).

---

## 4. IssuerSignedItem and IssuerSignedItemBytes

### 4.1 Keys and order

Each IssuerSignedItem is a CBOR map. For the circuit to find attributes correctly:

- **elementIdentifier** must **immediately precede** **elementValue** (adjacent key-value pairs).
- **digestID** must be present and match the digestID used in valueDigests for this item.
- **random** is required by ISO 18013-5 and must be **at least 16 bytes**.

Recommended key order (e.g. with BTreeMap or explicit ordering):  
`digestID`, `elementIdentifier`, `elementValue`, `random`.

### 4.2 IssuerSignedItemBytes in nameSpaces

- In the document’s **issuerSigned.nameSpaces**, each namespace maps to an **array** of **IssuerSignedItemBytes**.
- IssuerSignedItemBytes = **tag-24 encoding** of the **IssuerSignedItem** (the raw CBOR map bytes of the item).
- The digest in valueDigests for (namespace, digestID) must equal  
  `SHA256(EncodedCbor(IssuerSignedItem))`  
  i.e. SHA-256 of the same tag-24 encoding that appears in nameSpaces.

### 4.3 Attribute hash length

- The circuit limits attribute hash preimage to **two SHA-256 blocks** (128 bytes) for the disclosed attributes.
- IssuerSignedItem (and thus IssuerSignedItemBytes) length is constrained by random length, identifier length, value encoding, and CBOR overhead.

---

## 5. Issuer signature (credential hash message)

- Sign over **Sig_structure** per RFC 8152:  
  `["Signature1", protected, external_aad, payload]`
- **protected**: ES256 header bytes (3 bytes).
- **external_aad**: empty byte string (empty AAD).
- **payload**: the **tag-24 encoded MSO** (same bytes as in issuerAuth payload).
- The resulting credential hash message (encoded Sig_structure) is what is hashed for the issuer’s ECDSA; the circuit assumes the first 18 bytes are the fixed prefix above.

---

## 6. Document and DeviceResponse structure

- **docType**: text string.
- **issuerSigned**: map with **issuerAuth** (COSE_Sign1 array: protected, unprotected, payload, signature) and **nameSpaces** (map: namespace → array of tag-24 IssuerSignedItemBytes).
- **deviceSigned**: **nameSpaces** (tag-24 encoded DeviceNameSpacesBytes), **deviceAuth** (e.g. deviceSignature as COSE_Sign1).
- Device auth must be **device signature** (not MAC).
- Session transcript and docType used in DeviceAuthentication must match what the verifier/prover use.

---

## 7. Time and validity

- **time** (current time) in proofs must be a 20-character RFC 3339 string (e.g. `2024-06-15T12:00:00Z`).
- Circuit checks: `validFrom ≤ time ≤ validUntil` and that validFrom/validUntil are tag-0 text, 20 chars.

---

## 8. Checklist summary

When building an mdoc for use with mdoc_zk:

- [ ] MSO includes **version** (`"1.0"`) and **digestAlgorithm** (`"SHA-256"`) and key order is: version, digestAlgorithm, valueDigests, deviceKeyInfo, validityInfo.
- [ ] valueDigests: each digest = SHA256(tag24(IssuerSignedItem_bytes)); digestIDs and namespaces match nameSpaces.
- [ ] validityInfo: validFrom/validUntil are tag-0 text, 20 characters, RFC 3339.
- [ ] deviceKeyInfo: deviceKey first; EC2 P-256; x, y as 32-byte bstr.
- [ ] Issuer payload = tag-24(MSO_bytes).
- [ ] Issuer signed over Sig_structure(protected_ES256, "", tag24(MSO)); protected = 3-byte ES256.
- [ ] IssuerSignedItem: elementIdentifier immediately before elementValue; digestID present; random ≥ 16 bytes.
- [ ] nameSpaces: each item is tag-24(IssuerSignedItem_bytes); same bytes used for valueDigests digest input.
- [ ] Attribute hash preimage (tag24(item)) fits within circuit’s attribute hash input limits (e.g. two blocks).
- [ ] Credential length (MSO + Sig_structure overhead) within circuit’s maximum (e.g. 35 SHA-256 blocks).

---

## 9. Debugging helpers

If proof generation fails, the crate exposes helpers (see `mdoc_zk` module):

- **credential_hash_message_bytes(device_response)** — returns the credential hash message the library would use; compare with the bytes actually signed.
- **mso_offset_hints(device_response, namespace, attribute_ids)** — returns `(value_digests_offset, digest_offsets)`; compare with a known-good mdoc (e.g. test vector).
- **mso_bytes_from_device_response(device_response)** — returns raw MSO bytes; compare first bytes (e.g. map size, version/digestAlgorithm keys) with a working mdoc.

These were used during the e2e investigation to align the MSO with the circuit’s expectations (version/digestAlgorithm and key order).
