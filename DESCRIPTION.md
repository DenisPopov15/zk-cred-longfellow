# zk-cred-longfellow: How It Works

This document describes how to create and verify a zero-knowledge proof for an **ECDSA-signed mdoc** (ISO/IEC 18013-5 mobile document) using this library. The scheme is [Anonymous Credentials from ECDSA][anon-creds-ecdsa] (Longfellow), following the [draft libZK specification][draft-libzk].

---

## Overview

**What the proof shows (in zero-knowledge):**

1. **Issuer ECDSA signature** – You possess an mdoc that was signed by a known issuer (public key). The signature is over a **credential hash** (SHA-256 of the issuer-signed payload). You do not reveal the full credential or the signature bytes.

2. **Device ECDSA signature** – The same mdoc is bound to the current session via a **device binding signature** over a **session transcript hash**. You prove this without revealing the device private key or the raw signature.

3. **Selective disclosure** – You reveal only the **requested attributes** (e.g. “issue_date”, “family_name”) with their values. All other credential contents stay hidden.

4. **Validity and binding** – Validity window (validFrom/validUntil) and time are checked; the proof is bound to a specific **session transcript** and **time** (RFC 3339, 20 bytes, e.g. `2024-03-15T12:00:00Z`).

**Document format:** The “signed ECDSA document” is an ISO 18013-5 **DeviceResponse** (CBOR): it contains one **Document** with **IssuerSigned** (issuer ECDSA over the credential) and **DeviceSigned** (device ECDSA over the session). The library parses this and builds the ZK witness from it.

**Supported credential format:** This library supports **only the mdoc/CBOR (ISO 18013-5) structure**. It does **not** support [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) (W3VC) in JSON-LD, JWT, or other encodings. The circuits and parsers are built around **DeviceResponse**, **IssuerSigned**, **DeviceSigned**, COSE signatures, and CBOR-encoded attributes. To use W3C VCs you would need a different credential format adapter or a separate circuit design.

---

## Prerequisites

- **Circuit file** – A decompressed circuit file (two circuits: signature circuit and hash circuit) for the chosen **circuit version** (e.g. `CircuitVersion::V6`) and **number of disclosed attributes** (1–4). Circuit files are typically stored as zstd-compressed blobs and must be decompressed before use.
- **Issuer public key** – P-256, in SEC 1 uncompressed form (0x04 || x || y), as in X.509 `SubjectPublicKeyInfo`.
- **Session transcript** – CBOR-encoded **SessionTranscript** that both prover and verifier use (binding).
- **Time** – Current time in RFC 3339 format, UTC, exactly 20 characters (e.g. `2024-03-15T12:00:00Z`).

---

## Creating a ZKP (Prover)

### High-level flow

1. **Load the circuit** (decompressed bytes) and create a prover for a fixed number of attributes (1–4).
2. **Prepare inputs** from:
   - **DeviceResponse** (CBOR) – the mdoc with issuer and device ECDSA signatures
   - **Session transcript** (CBOR)
   - **Namespace** (e.g. `"org.iso.18013.5.1"`)
   - **Requested attribute IDs** (e.g. `["issue_date"]`)
   - **Time** (RFC 3339, 20 bytes)
3. **Run the prover** to get a single serialized proof (MAC tags + hash proof + signature proof).

Internally the library:

- Parses the DeviceResponse and extracts issuer public key, issuer signature, device public key, device signature, credential hash, session transcript hash, validity, and attribute digests.
- Fills **signature circuit** inputs: public (issuer key, session transcript hash, MAC tags, MAC verifier key share) and private (credential hash, device key, ECDSA witnesses for both signatures, MAC prover key shares).
- Fills **hash circuit** inputs: public (disclosed attributes, time, MAC tags, MAC verifier key share) and private (SHA-256 witnesses for credential and attributes, MAC prover key shares, offsets).
- Uses a **Fiat–Shamir transcript** (session transcript + commitments + challenges) so the MAC verifier key share is derived consistently between prover and verifier.
- Runs **Sumcheck** and **Ligero** for both circuits and serializes **MdocZkProof** (MAC tags, commitments, sumcheck proofs, Ligero proofs).

### Rust: create a proof

```rust
use zk_cred_longfellow::mdoc_zk::{CircuitVersion, prover::MdocZkProver};
use std::io::Read;

// 1. Load circuit file (decompressed)
let circuit_path = "test-vectors/mdoc_zk/6_1_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6";
let mut compressed = Vec::new();
std::fs::File::open(circuit_path)?.read_to_end(&mut compressed)?;
let circuit_bytes = zstd::decode_all(&compressed[..])?;

// 2. Initialize prover: circuit version V6, number of attributes to disclose = 1
let prover = MdocZkProver::new(&circuit_bytes, CircuitVersion::V6, 1)?;

// 3. Your mdoc (DeviceResponse CBOR), session transcript (CBOR), and time
let device_response: &[u8] = /* ... DeviceResponse bytes ... */;
let session_transcript: &[u8] = /* ... SessionTranscript CBOR ... */;
let namespace = "org.iso.18013.5.1";
let requested_claims = ["issue_date"];
let time = "2024-03-15T12:00:00Z"; // RFC 3339, UTC, 20 chars

// 4. Create the proof
let proof_bytes = prover.prove(
    device_response,
    namespace,
    &requested_claims,
    session_transcript,
    time,
)?;

// proof_bytes is the serialized MdocZkProof (to send to the verifier)
```

### JavaScript / WASM: create a proof

The WASM API exposes only the **prover** (no verifier in JS yet):

```javascript
import init, { initialize_prover, prove, CircuitVersion } from './pkg/zk_cred_longfellow.js';

await init();

// 1. Load and decompress circuit (e.g. fetch + pako/zstd decompress)
const circuitCompressed = await fetch('path/to/6_1_....zst').then(r => r.arrayBuffer());
const circuit = decompress(new Uint8Array(circuitCompressed)); // your zstd decompress

// 2. Initialize prover: V6, 1 attribute
const prover = initialize_prover(circuit, CircuitVersion.V6, 1);

// 3. Proof inputs
const deviceResponse = new Uint8Array([...]); // DeviceResponse CBOR
const namespace = "org.iso.18013.5.1";
const requestedClaims = ["issue_date"];
const sessionTranscript = new Uint8Array([...]); // SessionTranscript CBOR
const time = "2024-03-15T12:00:00Z";

// 4. Create proof (returns serialized proof or throws MdocZkError)
const proof = prove(
  prover,
  deviceResponse,
  namespace,
  requestedClaims,
  sessionTranscript,
  time
);
```

---

## Verifying a ZKP (Verifier)

Verification is implemented in Rust only (not exposed in the current WASM/JS API).

### What the verifier checks

- **Same binding** – Uses the same **session transcript** and **time** to derive the MAC verifier key share and to build the **CircuitStatements** (public inputs).
- **Issuer** – Uses the **issuer public key** (SEC 1) you provide.
- **Disclosed attributes** – You pass the list of **attributes** (identifier + value CBOR) that were disclosed; the verifier checks they match the public part of the proof.
- **Document type and device namespaces** – For correct session transcript hash and mdoc authentication context: **doc_type** and **device_name_spaces_bytes** (from the DeviceResponse) must be supplied by the verifier (e.g. from a previous handover or from the prover in the clear).

The verifier then:

1. Decodes the serialized **MdocZkProof** (MAC tags, hash/signature commitments, sumcheck proofs, Ligero proofs).
2. Rebuilds the Fiat–Shamir transcript (session transcript, then commitments, then challenge for MAC verifier key share).
3. Builds **CircuitStatements** (public inputs) for hash and signature circuits from: issuer key, disclosed attributes, doc_type, device_name_spaces_bytes, session transcript, time, proof MAC tags, and MAC verifier key share.
4. Runs **Sumcheck** and **Ligero** verification for the hash circuit, then for the signature circuit.

If all checks pass, the verifier accepts that:

- The prover holds an mdoc signed by the given issuer (ECDSA over the credential hash).
- The prover proved the device binding ECDSA over the session transcript.
- The disclosed attributes are consistent with that credential and with the stated time and session.

### Rust: verify a proof

```rust
use zk_cred_longfellow::mdoc_zk::{
    CircuitVersion,
    verifier::{MdocZkVerifier, Attribute},
};

// 1. Same circuit file as prover (decompressed)
let circuit_bytes = /* ... same as prover ... */;

// 2. Initialize verifier: same version and same number of attributes as prover
let verifier = MdocZkVerifier::new(&circuit_bytes, CircuitVersion::V6, 1)?;

// 3. Issuer public key (SEC 1: 0x04 || x || y), e.g. from issuer certificate
let issuer_public_key_sec1: &[u8] = /* ... 65 bytes ... */;

// 4. Attributes that were disclosed (identifier + value in CBOR)
let attributes = [
    Attribute {
        identifier: "issue_date".to_string(),
        value_cbor: vec![0xd9, 0x03, 0xec, 0x6a, 0x32, 0x30, 0x32, 0x34, 0x2d, 0x30, 0x33, 0x2d, 0x31, 0x35], // e.g. "2024-03-15"
    },
];

// 5. Context from the mdoc/session (verifier must know these)
let doc_type = "org.iso.18013.5.1.mDL";
let device_name_spaces_bytes: &[u8] = &[0xA0]; // e.g. empty CBOR map
let session_transcript: &[u8] = /* same as prover */;
let time = "2024-03-15T12:00:00Z";

// 6. Serialized proof from the prover
let proof: &[u8] = /* ... */;

verifier.verify(
    issuer_public_key_sec1,
    &attributes,
    doc_type,
    device_name_spaces_bytes,
    session_transcript,
    time,
    proof,
)?;
// Ok(()) means the proof is valid
```

---

## Data Flow Summary

| Role    | Inputs | Output |
|--------|--------|--------|
| Prover | DeviceResponse (CBOR), session transcript, namespace, requested attribute IDs, time | Serialized **MdocZkProof** |
| Verifier | Issuer public key (SEC 1), disclosed attributes (id + value_cbor), doc_type, device_name_spaces_bytes, session transcript, time, **proof** | Accept / Reject |

The **session transcript** and **time** must match between prover and verifier. The verifier must also know **doc_type** and **device_name_spaces_bytes** (they are not hidden by the proof) to recompute the session transcript hash and build the correct public inputs.

---

## Circuit and Proof Format

- **Two circuits:** one for **signature verification** (P-256 field), one for **hashing and structure** (GF(2^128) and related structure). Both are encoded in the same circuit file (signature first, then hash).
- **Proof contents:** MAC tags (6 × GF(2^128)), hash commitment, hash sumcheck proof, hash Ligero proof, signature commitment, signature sumcheck proof, signature Ligero proof. Encoding is per draft libZK and depends on **ProofContext** (circuit and layout references).
- **Circuit files:** Named by circuit version and number of attributes (e.g. `6_1_<hash>.zst`). Must be decompressed before passing to `MdocZkProver::new` / `MdocZkVerifier::new`.

---

## E2E test example: balance proof

The repo includes an end-to-end integration test that:

1. **Builds a signed mdoc** with a single attribute `balance = 100000` and a holder identity (e.g. `did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH`). The issuer and device keys are P-256; the issuer uses a self-signed certificate in the mdoc.
2. **Creates a ZK proof** that discloses the `balance` attribute and proves valid issuer and device ECDSA signatures.
3. **Verifies the proof** with the issuer public key and the disclosed attribute (balance = 100000).
4. **Checks the predicate** that the disclosed balance is greater than 50000 (done in the clear after verification).

Run the test (with output):

```sh
cargo test --test e2e_balance_proof e2e_balance_proof -- --nocapture
```

The test lives in `tests/e2e_balance_proof.rs`. It generates the mdoc in-process (CBOR, ISO 18013-5 shape with namespace `org.example.balance`), loads the 1-attribute circuit from `test-vectors/mdoc_zk/`, and runs the prover and verifier. The “balance > 50000” condition is enforced by the verifier application after a successful proof verification; the circuit itself only proves signature validity and selective disclosure of the balance value.

---

## References

- [Anonymous Credentials from ECDSA][anon-creds-ecdsa] (Longfellow)
- [draft libZK][draft-libzk] (IETF)
- [ISO/IEC 18013-5][iso-18013-5] (mdoc / mDL)

[anon-creds-ecdsa]: https://eprint.iacr.org/2024/2010.pdf
[draft-libzk]: https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/
[iso-18013-5]: https://www.iso.org/standard/69084.html
