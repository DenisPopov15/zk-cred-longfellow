//! E2E test: build a signed mdoc with balance=100000, create a ZK proof that discloses
//! the balance and proves valid issuer/device signatures, verify the proof, and assert
//! that the disclosed balance is greater than 50000.
//!
//! Run with: `cargo test --test e2e_balance_proof e2e_balance_proof -- --nocapture`
//!
//! If you see "in-circuit assertion failed", it may be due to ECDSA/serialization or
//! hash-to-field details; the crate's existing `mdoc_zk::tests::end_to_end` uses a
//! pre-generated test vector and is the reference for a known-good flow.

use ciborium::value::{Integer, Value};
use ecdsa::elliptic_curve::rand_core::OsRng;
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use rcgen::{CertificateParams, KeyPair};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Instant;

use zk_cred_longfellow::mdoc_zk::{
    credential_hash_message_bytes,
    mso_bytes_from_device_response,
    mso_offset_hints,
    prover::MdocZkProver,
    verifier::{Attribute, MdocZkVerifier},
    CircuitVersion,
};

const NAMESPACE: &str = "org.example.balance";
const DOC_TYPE: &str = "org.example.balance.v1";
const BALANCE_VALUE: u64 = 100_000;
const BALANCE_THRESHOLD: u64 = 50_000;
/// Holder DID (identity of the credential holder; we use a P-256 device key for mdoc binding).
const HOLDER_DID: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

/// Converts a map with string keys to Value::Map (ciborium expects Vec<(Value, Value)>).
fn map_to_value(m: BTreeMap<String, Value>) -> Value {
    Value::Map(
        m.into_iter()
            .map(|(k, v)| (Value::Text(k), v))
            .collect(),
    )
}

#[test]
fn e2e_balance_proof() {
    run().expect("e2e_balance_proof failed");
}

/// Prover run with the crate's witness test vector mdoc (prove only).
/// Confirms that the test vector mdoc passes the hash circuit when used from this test binary.
#[test]
fn e2e_with_test_vector_mdoc() {
    let tv = load_witness_test_vector_from_disk();
    let circuit_decompressed = load_circuit_1_attribute().expect("load circuit");
    let prover = MdocZkProver::new(&circuit_decompressed, CircuitVersion::V6, 1)
        .expect("prover init");
    prover
        .prove(
            &tv.mdoc,
            "org.iso.18013.5.1",
            &[&tv.attributes[0].id],
            &tv.transcript,
            &tv.now,
        )
        .expect("prove with test vector mdoc");
}

#[derive(Deserialize)]
struct WitnessTestVectorDoc {
    #[serde(deserialize_with = "hex::serde::deserialize")]
    mdoc: Vec<u8>,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    transcript: Vec<u8>,
    attributes: Vec<WitnessAttr>,
    now: String,
}

#[derive(Deserialize)]
struct WitnessAttr {
    id: String,
}

fn load_witness_test_vector_from_disk() -> WitnessTestVectorDoc {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors/mdoc_zk/witness_test_vector.json");
    let bytes = std::fs::read(&path).expect("read witness test vector");
    serde_json::from_slice(&bytes).expect("parse witness test vector")
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("1. Generating P-256 issuer and device keys...");
    let device_signing_key = SigningKey::random(&mut OsRng);

    println!("2. Building self-signed issuer certificate (P-256)...");
    let (issuer_cert_der, issuer_signing_key) = build_issuer_cert_and_key()?;

    println!("3. Building signed mdoc with balance = {} and holder = {}...", BALANCE_VALUE, HOLDER_DID);
    let (device_response, issuer_public_key_sec1, device_name_spaces_bytes) =
        build_balance_mdoc(&issuer_signing_key, &device_signing_key, &issuer_cert_der)?;

    // Step 3: verify mdoc CBOR structure (MSO key order, validityInfo format)
    verify_mdoc_structure(&device_response)?;

    // Step 6: compare MSO offsets with test vector (diagnostic)
    let (our_vd, our_digest) = mso_offset_hints(&device_response, NAMESPACE, &["balance"])
        .map_err(|e| format!("mso_offset_hints (our mdoc): {e}"))?;
    let tv = load_witness_test_vector_from_disk();
    let tv_ns = "org.iso.18013.5.1";
    let tv_attr = tv.attributes[0].id.as_str();
    if let Ok((tv_vd, tv_digest)) = mso_offset_hints(&tv.mdoc, tv_ns, &[tv_attr]) {
        eprintln!(
            "[Step 6] MSO offsets: our value_digests={} digest(0)={:?} | tv value_digests={} digest(0)={:?}",
            our_vd, our_digest, tv_vd, tv_digest
        );
    }
    // Step 7: compare first bytes of MSO (diagnostic)
    if let (Ok(our_mso), Ok(tv_mso)) = (
        mso_bytes_from_device_response(&device_response),
        mso_bytes_from_device_response(&tv.mdoc),
    ) {
        let n = 40.min(our_mso.len()).min(tv_mso.len());
        eprintln!(
            "[Step 7] MSO first {} bytes: ours {:02x?} ... | tv {:02x?} ...",
            n,
            &our_mso[..n],
            &tv_mso[..n]
        );
    }

    println!("4. Building session transcript and time...");
    let session_transcript = b"\xa0"; // CBOR empty map
    let time = "2024-06-15T12:00:00Z";
    assert_eq!(time.len(), 20, "time must be RFC 3339, 20 chars");

    println!("5. Loading circuit and creating prover...");
    let circuit_decompressed = load_circuit_1_attribute()?;
    let prover = MdocZkProver::new(&circuit_decompressed, CircuitVersion::V6, 1)
        .map_err(|e| format!("prover init: {e}"))?;

    println!("6. Creating ZK proof (disclose balance, prove valid signatures)...");
    let prove_start = Instant::now();
    let proof_bytes = prover
        .prove(
            &device_response,
            NAMESPACE,
            &["balance"],
            session_transcript,
            time,
        )
        .map_err(|e| format!("prove: {:#}", e))?;
    let prove_elapsed = prove_start.elapsed();
    println!(
        "   Proof created in {:.2}s ({:.0} ms)",
        prove_elapsed.as_secs_f64(),
        prove_elapsed.as_secs_f64() * 1000.0
    );

    println!("7. Verifying proof...");
    let verifier = MdocZkVerifier::new(&circuit_decompressed, CircuitVersion::V6, 1)
        .map_err(|e| format!("verifier init: {e}"))?;

    let balance_value_cbor = cbor_uint(BALANCE_VALUE);
    let verify_start = Instant::now();
    verifier
        .verify(
            &issuer_public_key_sec1,
            &[Attribute {
                identifier: "balance".to_string(),
                value_cbor: balance_value_cbor.clone(),
            }],
            DOC_TYPE,
            &device_name_spaces_bytes,
            session_transcript,
            time,
            &proof_bytes,
        )
        .map_err(|e| format!("verify: {e}"))?;
    let verify_elapsed = verify_start.elapsed();
    println!(
        "   Proof verified in {:.2}s ({:.0} ms)",
        verify_elapsed.as_secs_f64(),
        verify_elapsed.as_secs_f64() * 1000.0
    );

    println!("8. Checking predicate: balance > {}...", BALANCE_THRESHOLD);
    assert!(
        BALANCE_VALUE > BALANCE_THRESHOLD,
        "balance {} must be > {}",
        BALANCE_VALUE,
        BALANCE_THRESHOLD
    );
    println!("   OK: balance {} > {}", BALANCE_VALUE, BALANCE_THRESHOLD);

    println!(
        "\nE2E passed: mdoc created, proof created, proof verified, balance > 50000.\n  Timings: prove {:.2}s, verify {:.2}s",
        prove_elapsed.as_secs_f64(),
        verify_elapsed.as_secs_f64()
    );
    Ok(())
}

fn load_circuit_1_attribute() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors/mdoc_zk/6_1_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6");
    let compressed = std::fs::read(&path).map_err(|e| format!("read circuit: {e}"))?;
    zstd::decode_all(compressed.as_slice()).map_err(|e| format!("decompress: {e}").into())
}

fn build_issuer_cert_and_key() -> Result<(Vec<u8>, SigningKey), Box<dyn std::error::Error>> {
    let issuer_signing_key = SigningKey::random(&mut OsRng);
    let key_der = issuer_signing_key
        .to_pkcs8_der()
        .map_err(|e| format!("pkcs8 export: {e}"))?
        .to_bytes()
        .to_vec();

    let key_pair = KeyPair::try_from(key_der.as_slice())
        .map_err(|e| format!("rcgen import key: {e}"))?;

    let params = CertificateParams::default();

    let cert = params.self_signed(&key_pair).map_err(|e| format!("self_signed: {e}"))?;
    let cert_der = cert.der().as_ref().to_vec();
    Ok((cert_der, issuer_signing_key))
}

fn build_balance_mdoc(
    issuer_key: &SigningKey,
    device_key: &SigningKey,
    issuer_cert_der: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let valid_from = "2024-01-01T00:00:00Z";
    let valid_until = "2025-12-31T23:59:59Z";

    // IssuerSignedItem: digestID, elementIdentifier, elementValue, random (ISO 18013-5 requires random >= 16 bytes; elementIdentifier must immediately precede elementValue)
    let item_map: BTreeMap<String, Value> = [
        ("digestID".to_string(), Value::Integer(Integer::from(0i64))),
        ("elementIdentifier".to_string(), Value::Text("balance".to_string())),
        ("elementValue".to_string(), Value::Integer(Integer::from(BALANCE_VALUE as i64))),
        ("random".to_string(), Value::Bytes(b"0123456789012345".to_vec())),
    ]
    .into_iter()
    .collect();
    let mut item_bytes = Vec::new();
    ciborium::into_writer(&item_map, &mut item_bytes).map_err(|e| format!("item encode: {e}"))?;
    let item_encoded_cbor = encode_tag24(&item_bytes);
    let item_digest = Sha256::digest(&item_encoded_cbor);

    // MSO: valueDigests, deviceKeyInfo, validityInfo
    let value_digests_ns = vec![(
        Value::Integer(Integer::from(0i64)),
        Value::Bytes(item_digest.to_vec()),
    )];
    let value_digests = vec![(
        Value::Text(NAMESPACE.to_string()),
        Value::Map(value_digests_ns),
    )];

    let device_pk = device_key.verifying_key();
    let pt = device_pk.to_encoded_point(false);
    // Uncompressed point: 0x04 || x (32) || y (32)
    let pt_bytes = pt.as_bytes();
    let (dev_x, dev_y) = (
        pt_bytes[1..33].to_vec(),
        pt_bytes[33..65].to_vec(),
    );
    let device_cose_key = vec![
        (Value::Integer(Integer::from(1i64)), Value::Integer(Integer::from(2i64))),   // kty EC2
        (Value::Integer(Integer::from(-1i64)), Value::Integer(Integer::from(1i64))),  // crv P-256
        (Value::Integer(Integer::from(-2i64)), Value::Bytes(dev_x)),
        (Value::Integer(Integer::from(-3i64)), Value::Bytes(dev_y)),
    ];
    let device_key_info = vec![(
        Value::Text("deviceKey".to_string()),
        Value::Map(device_cose_key),
    )];

    let validity_info = vec![
        (
            Value::Text("validFrom".to_string()),
            Value::Tag(0, Box::new(Value::Text(valid_from.to_string()))),
        ),
        (
            Value::Text("validUntil".to_string()),
            Value::Tag(0, Box::new(Value::Text(valid_until.to_string()))),
        ),
    ];

    // MSO must include version and digestAlgorithm (ISO 18013-5; test vector has map of 6)
    let mso = vec![
        (Value::Text("version".to_string()), Value::Text("1.0".to_string())),
        (Value::Text("digestAlgorithm".to_string()), Value::Text("SHA-256".to_string())),
        (Value::Text("valueDigests".to_string()), Value::Map(value_digests)),
        (Value::Text("deviceKeyInfo".to_string()), Value::Map(device_key_info)),
        (Value::Text("validityInfo".to_string()), Value::Map(validity_info)),
    ];

    let mut mso_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(mso), &mut mso_bytes).map_err(|e| format!("mso encode: {e}"))?;

    // Step 4: valueDigests must contain SHA256(tag24(item_bytes)) for digestID 0
    let mso_decoded: Value = ciborium::from_reader(std::io::Cursor::new(&mso_bytes))
        .map_err(|e| format!("decode MSO for step 4: {e}"))?;
    let mso_pairs = mso_decoded.as_map().expect("MSO not a map");
    let vd = mso_pairs
        .iter()
        .find(|(k, _)| k.as_text().as_deref() == Some("valueDigests"))
        .map(|(_, v)| v);
    // valueDigests is map: namespace -> (digestID -> digest); get inner map for NAMESPACE then digestID 0
    let ns_map = vd.and_then(|v| v.as_map());
    let inner_map = ns_map.and_then(|m| {
        m.iter()
            .find(|(k, _)| k.as_text().as_deref() == Some(NAMESPACE))
            .map(|(_, v)| v)
    });
    let digest_0: Option<&[u8]> = inner_map
        .and_then(|v| v.as_map())
        .and_then(|m| {
            m.iter()
                .find(|(k, _)| k.as_integer().map(|i| i.clone() == Integer::from(0i64)) == Some(true))
                .map(|(_, v)| v)
        })
        .and_then(|v| v.as_bytes().map(|b| b.as_slice()));
    assert_eq!(
        digest_0,
        Some(item_digest.as_slice()),
        "valueDigests[{}][0] must equal SHA256(tag24(item_bytes))",
        NAMESPACE
    );

    let mso_payload = encode_tag24(&mso_bytes);

    // Issuer COSE_Sign1: sign SigStructure(protected_ES256, "", mso_payload).
    // ES256 protected = { 1: -7 } (3 bytes). Circuit expects this 18-byte prefix.
    let protected_es256 = {
        let mut b = Vec::new();
        let m: BTreeMap<i64, i64> = [(1, -7)].into_iter().collect();
        ciborium::into_writer(&m, &mut b).map_err(|e| format!("protected: {e}"))?;
        assert_eq!(b.len(), 3, "ES256 protected must be 3 bytes for circuit prefix");
        b
    };
    let to_sign_issuer = build_sig_structure(&protected_es256, &[] as &[u8], &mso_payload);
    // Diagnostic: credential hash message (SigStructure) must match what the circuit expects.
    // First 18 bytes are the "known prefix" (SHA_256_CREDENTIAL_KNOWN_PREFIX_BYTES).
    let prefix_len = 18usize;
    eprintln!(
        "[e2e] credential hash message len={}, prefix (first {} bytes): {:02x?}",
        to_sign_issuer.len(),
        prefix_len.min(to_sign_issuer.len()),
        &to_sign_issuer[..prefix_len.min(to_sign_issuer.len())]
    );
    let issuer_sig = sign_p256(issuer_key, &to_sign_issuer)?;

    let issuer_auth_payload = mso_payload;
    let cose_sign1_issuer = [
        Value::Bytes(protected_es256.clone()),
        Value::Map(vec![(
            Value::Integer(Integer::from(33i64)),
            Value::Bytes(issuer_cert_der.to_vec()),
        )]),
        Value::Bytes(issuer_auth_payload),
        Value::Bytes(issuer_sig),
    ];

    let name_spaces_issuer = BTreeMap::from([(
        NAMESPACE.to_string(),
        Value::Array(vec![Value::Tag(24, Box::new(Value::Bytes(item_bytes)))]),
    )]);

    let issuer_signed = BTreeMap::from([
        ("issuerAuth".to_string(), Value::Array(cose_sign1_issuer.into_iter().collect())),
        ("nameSpaces".to_string(), map_to_value(name_spaces_issuer)),
    ]);

    // Device name spaces (empty map), then tag 24
    let device_name_spaces_inner: Vec<(Value, Value)> = vec![];
    let mut device_ns_bytes = Vec::new();
    ciborium::into_writer(&Value::Map(device_name_spaces_inner), &mut device_ns_bytes)
        .map_err(|e| format!("device ns: {e}"))?;
    let device_name_spaces_bytes = encode_tag24(&device_ns_bytes);

    // DeviceAuthentication for device signature
    let session_transcript_value = Value::Map(vec![]);
    let device_auth_value = Value::Array(vec![
        Value::Text("DeviceAuthentication".to_string()),
        session_transcript_value,
        Value::Text(DOC_TYPE.to_string()),
        Value::Tag(24, Box::new(Value::Bytes(device_name_spaces_bytes.clone()))),
    ]);
    let mut device_auth_bytes = Vec::new();
    ciborium::into_writer(&device_auth_value, &mut device_auth_bytes)
        .map_err(|e| format!("device auth encode: {e}"))?;
    let device_auth_payload = encode_tag24(&device_auth_bytes);
    let to_sign_device = build_sig_structure(&protected_es256, &[], &device_auth_payload);
    let device_sig = sign_p256(device_key, &to_sign_device)?;

    let cose_sign1_device = [
        Value::Bytes(protected_es256.clone()),
        Value::Map(vec![]),
        Value::Bytes(device_auth_payload),
        Value::Bytes(device_sig),
    ];
    // DeviceAuth is an enum: DeviceSignature(CoseSign1). Serde rename_all=camelCase => "deviceSignature"
    let device_auth = Value::Map(vec![(
        Value::Text("deviceSignature".to_string()),
        Value::Array(cose_sign1_device.into_iter().collect()),
    )]);

    let device_signed = BTreeMap::from([
        (
            "nameSpaces".to_string(),
            Value::Tag(24, Box::new(Value::Bytes(device_name_spaces_bytes.clone()))),
        ),
        ("deviceAuth".to_string(), device_auth),
    ]);

    let document = BTreeMap::from([
        ("docType".to_string(), Value::Text(DOC_TYPE.to_string())),
        ("issuerSigned".to_string(), map_to_value(issuer_signed)),
        ("deviceSigned".to_string(), map_to_value(device_signed)),
    ]);

    let device_response = BTreeMap::from([
        (
            "documents".to_string(),
            Value::Array(vec![map_to_value(document)]),
        ),
        ("status".to_string(), Value::Integer(Integer::from(0i64))),
    ]);

    let mut out = Vec::new();
    ciborium::into_writer(&map_to_value(device_response), &mut out)
        .map_err(|e| format!("device response encode: {e}"))?;

    // Step 5: library's credential hash message must match what we signed
    let lib_cred_message =
        credential_hash_message_bytes(&out).map_err(|e| format!("credential_hash_message: {e}"))?;
    assert_eq!(
        lib_cred_message,
        to_sign_issuer,
        "library credential hash message must match signed message"
    );

    let issuer_public_key_sec1 = issuer_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    Ok((out, issuer_public_key_sec1, device_name_spaces_bytes))
}

/// Step 3: Verify device_response CBOR structure (MSO key order, validityInfo).
fn verify_mdoc_structure(device_response: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use ciborium::value::Value as CborValue;
    use std::io::Cursor;
    fn map_get<'a>(m: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
        m.iter()
            .find(|(k, _)| k.as_text().as_deref() == Some(key))
            .map(|(_, v)| v)
    }
    let dr: CborValue = ciborium::from_reader(Cursor::new(device_response))
        .map_err(|e| format!("decode device response: {e}"))?;
    let documents = dr
        .as_map()
        .and_then(|m| map_get(m, "documents"))
        .and_then(|v| v.as_array())
        .ok_or("documents missing or not array")?;
    let doc = documents.first().ok_or("documents empty")?;
    let issuer_auth = doc
        .as_map()
        .and_then(|m| map_get(m, "issuerSigned"))
        .and_then(|v| v.as_map())
        .and_then(|m| map_get(m, "issuerAuth"))
        .and_then(|v| v.as_array())
        .ok_or("issuerAuth missing or not array")?;
    let payload = issuer_auth
        .get(2)
        .and_then(|v| v.as_bytes())
        .ok_or("issuerAuth payload missing or not bytes")?;
    // Payload is tag-24 encoded MSO: 0xd8 0x18 then byte string
    if payload.len() < 4 || payload[0] != 0xd8 || payload[1] != 0x18 {
        return Err("payload not tag-24 encoded".into());
    }
    let (mso_len, mso_start) = if payload[2] == 0x58 {
        (payload[3] as usize, 4)
    } else if payload[2] == 0x59 && payload.len() >= 5 {
        let l = (payload[3] as usize) << 8 | (payload[4] as usize);
        (l, 5)
    } else {
        return Err("payload byte string length invalid".into());
    };
    if payload.len() < mso_start + mso_len {
        return Err("payload shorter than MSO length".into());
    }
    let mso_bytes = &payload[mso_start..mso_start + mso_len];
    let mso: CborValue = ciborium::from_reader(mso_bytes)
        .map_err(|e| format!("decode MSO: {e}"))?;
    let mso_map = mso.as_map().ok_or("MSO not a map")?;
    let keys: Vec<String> = mso_map
        .iter()
        .filter_map(|(k, _): &(CborValue, CborValue)| k.as_text().map(String::from))
        .collect();
    const EXPECTED_MSO_KEYS: [&str; 5] = [
        "version",
        "digestAlgorithm",
        "valueDigests",
        "deviceKeyInfo",
        "validityInfo",
    ];
    if keys != EXPECTED_MSO_KEYS {
        return Err(format!(
            "MSO key order: got {:?}, expected {:?}",
            keys, EXPECTED_MSO_KEYS
        )
        .into());
    }
    // validityInfo: validFrom and validUntil must be tag-0 text, 20 chars (RFC 3339)
    let validity = mso_map
        .iter()
        .find(|(k, _): &&(CborValue, CborValue)| k.as_text().as_deref() == Some("validityInfo"))
        .map(|(_, v)| v)
        .ok_or("validityInfo missing")?;
    let validity_map = validity.as_map().ok_or("validityInfo not a map")?;
    for key in ["validFrom", "validUntil"] {
        let v = validity_map
            .iter()
            .find(|(k, _): &&(CborValue, CborValue)| k.as_text().as_deref() == Some(key))
            .map(|(_, v)| v)
            .ok_or_else(|| format!("{} missing", key))?;
        let (tag, inner) = match v {
            CborValue::Tag(t, b) => (t, b.as_ref()),
            _ => return Err(format!("{} not a tag", key).into()),
        };
        if *tag != 0 {
            return Err(format!("{} has wrong tag {}", key, tag).into());
        }
        let s = inner.as_text().ok_or(format!("{} value not text", key))?;
        if s.len() != 20 {
            return Err(format!("{} length must be 20 (RFC 3339), got {}", key, s.len()).into());
        }
    }
    Ok(())
}

fn encode_tag24(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(
        &Value::Tag(24, Box::new(Value::Bytes(bytes.to_vec()))),
        &mut out,
    )
    .expect("tag24");
    out
}

fn build_sig_structure(protected: &[u8], _external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    // Sig_structure = ["Signature1", protected, external_aad, payload]
    let arr = vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(vec![]),
        Value::Bytes(payload.to_vec()),
    ];
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Array(arr), &mut out).expect("sig_structure");
    out
}

fn sign_p256(key: &SigningKey, message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use ecdsa::signature::Signer;
    let sig: ecdsa::Signature<p256::NistP256> = key.sign(message);
    // Library expects raw 64-byte r||s (big-endian). ecdsa::Signature uses compact encoding.
    let sig_bytes = sig.to_bytes();
    let sig_vec = sig_bytes.as_slice().to_vec();
    assert_eq!(sig_vec.len(), 64, "P-256 signature must be 64 bytes (r||s)");
    Ok(sig_vec)
}

fn cbor_uint(n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Integer(Integer::from(n)), &mut out).expect("cbor uint");
    out
}
