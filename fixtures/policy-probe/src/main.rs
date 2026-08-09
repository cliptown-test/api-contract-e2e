//! Drives the pinned backend's own policy modules with adversarial input.
//!
//! The four modules below are copied VERBATIM at run time by
//! `scripts/run-e2e.sh` out of the backend checkout it materialized at the SHA
//! in `test-plan.json`, into this crate's scratch copy. They are NOT vendored
//! into this repository, and the copy is a byte-for-byte `cp` of the pinned
//! file — `scripts/run-e2e.sh` checksums each one and prints the digest. If the
//! pinned source changes, this probe compiles the changed source and its
//! verdicts change with it, which is the whole point: a suite that transcribed
//! the rules would agree with its own transcription errors.
//!
//! (They are copied rather than `include!`d because each pinned file opens with
//! `//!` inner doc comments, which `include!` inside a `mod` block rejects.)
//!
//! This exists because `cliptown-api` is a binary crate whose domain modules
//! are compiled in but mounted on no route, so `curl` cannot reach any of the
//! authorization, idempotency or object-manifest logic. The modules' own unit
//! tests exercise them with benign inputs; this probe attacks them.
//!
//! Output contract, one record per line, consumed by run-e2e.sh:
//!   PASS|<id>|<message>|
//!   FAIL|<id>|<message>|
//!   DEFECT|<id>|<message>|<reproduction>

#![allow(dead_code)]

// Populated by scripts/run-e2e.sh from the pinned backend checkout.
mod account_security;
mod app_vault;
mod encrypted_objects;
mod memebank_transfer;

use chrono::{TimeZone, Utc};
use cliptown_interfaces_rust::{ExternalStepUpAction, ExternalStepUpProof};

use account_security::DeviceLifecycleState;
use app_vault::{
    validate_step_up_authorization, AuthenticatedDevice, PolicyError as VaultError,
    ProtectedRequestContext, StepUpChallenge, StepUpPolicy, StepUpSignatureVerifier,
};
use encrypted_objects::{
    EncryptedObjectChunk, EncryptedObjectManifest, ObjectGrantPolicy, WrappedContentKey,
};
use memebank_transfer::{
    evaluate_idempotency, IdempotencyBinding, IdempotencyDecision, IdempotentOperation,
    PolicyError as TransferError,
};

fn ok(id: &str, message: &str) {
    println!("PASS|{id}|{message}|");
}
fn no(id: &str, message: &str) {
    println!("FAIL|{id}|{message}|");
}
fn defect(id: &str, message: &str, repro: &str) {
    println!("DEFECT|{id}|{message}|{repro}");
}

const NOW: i64 = 1_800_000_000;
const DIGEST: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const SUBJECT: &str = "aaaaaaaa-0000-4000-8000-00000000000a";
const DEVICE_A1: &str = "device-a1";
const DEVICE_A2: &str = "device-a2";

/// Signature verification is the external 3FA issuer's job, not this policy
/// layer's. Accepting every signature isolates exactly what the binding logic
/// contributes: if a proof is refused here, it is refused on context alone.
struct SignatureAlwaysValid;
impl StepUpSignatureVerifier for SignatureAlwaysValid {
    fn verify(&self, _: &ExternalStepUpProof) -> Result<(), VaultError> {
        Ok(())
    }
}

fn proof_for(device_id: &str, challenge_id: &str) -> ExternalStepUpProof {
    ExternalStepUpProof {
        protocol_version: 1,
        proof_id: "proof-0001".into(),
        issuer: "https://3fa.app".into(),
        subject: SUBJECT.into(),
        audience: "cliptown".into(),
        device_id: device_id.into(),
        challenge_id: challenge_id.into(),
        action: ExternalStepUpAction::RevokeDevice,
        issued_at: Utc.timestamp_opt(NOW - 10, 0).unwrap(),
        expires_at: Utc.timestamp_opt(NOW + 100, 0).unwrap(),
        signing_key_id: "3fa-key-1".into(),
        signature: "A".repeat(64),
    }
}

fn challenge_for<'a>(challenge_id: &'a str, device_id: &'a str) -> StepUpChallenge<'a> {
    StepUpChallenge {
        challenge_id,
        subject: SUBJECT,
        initiating_device_id: device_id,
        audience: "cliptown",
        action: ExternalStepUpAction::RevokeDevice,
        method: "POST",
        normalized_route: "/v1/devices/revoke",
        target_resource_id: Some("device-victim"),
        request_body_sha256_base64: DIGEST,
        created_at_unix_seconds: NOW - 20,
        expires_at_unix_seconds: NOW + 100,
        consumed: false,
        invalidated: false,
    }
}

fn request_for(device_id: &str) -> ProtectedRequestContext<'_> {
    ProtectedRequestContext {
        subject: SUBJECT,
        initiating_device_id: device_id,
        action: ExternalStepUpAction::RevokeDevice,
        method: "POST",
        normalized_route: "/v1/devices/revoke",
        target_resource_id: Some("device-victim"),
        request_body_sha256_base64: DIGEST,
    }
}

fn device(device_id: &str, state: DeviceLifecycleState) -> AuthenticatedDevice<'_> {
    AuthenticatedDevice {
        subject: SUBJECT,
        device_id,
        lifecycle_state: state,
    }
}

// --- auth / device binding ---------------------------------------------------

fn step_up_checks() {
    let policy = StepUpPolicy::default();
    let verifier = SignatureAlwaysValid;

    // Baseline: the honest ceremony must succeed, otherwise every negative
    // below would pass for the wrong reason.
    let happy = validate_step_up_authorization(
        NOW,
        &request_for(DEVICE_A1),
        &challenge_for("challenge-1", DEVICE_A1),
        &proof_for(DEVICE_A1, "challenge-1"),
        device(DEVICE_A1, DeviceLifecycleState::Active),
        policy,
        &verifier,
    );
    match happy {
        Ok(_) => ok(
            "PP1",
            "step-up: a fully consistent subject/device/challenge/proof is authorized (so the negatives below are not passing vacuously)",
        ),
        Err(e) => no(
            "PP1",
            &format!("step-up: the honest ceremony was refused with {e:?}"),
        ),
    }

    // A device that is not the challenge's initiating device must not consume it.
    let wrong_device = validate_step_up_authorization(
        NOW,
        &request_for(DEVICE_A2),
        &challenge_for("challenge-1", DEVICE_A1),
        &proof_for(DEVICE_A1, "challenge-1"),
        device(DEVICE_A2, DeviceLifecycleState::Active),
        policy,
        &verifier,
    );
    if wrong_device.is_err() {
        ok("PP2", "step-up: a sibling device cannot consume another device's challenge (request/challenge device binding holds)");
    } else {
        no(
            "PP2",
            "step-up: a sibling device consumed a challenge initiated by a different device",
        );
    }

    // A revoked or otherwise inactive device must never step up, however
    // consistent the rest of the paperwork.
    for state in [
        DeviceLifecycleState::Revoked,
        DeviceLifecycleState::Suspended,
        DeviceLifecycleState::Pending,
    ] {
        let inactive = validate_step_up_authorization(
            NOW,
            &request_for(DEVICE_A1),
            &challenge_for("challenge-1", DEVICE_A1),
            &proof_for(DEVICE_A1, "challenge-1"),
            device(DEVICE_A1, state),
            policy,
            &verifier,
        );
        if inactive.is_err() {
            ok("PP3", &format!("step-up: a {state:?} device is refused"));
        } else {
            no("PP3", &format!("step-up: a {state:?} device was authorized"));
        }
    }

    // THE ONE THAT MATTERS. The proof carries its own `device_id`. Point it at a
    // device that has nothing to do with this challenge and change nothing else.
    let foreign_proof_device = validate_step_up_authorization(
        NOW,
        &request_for(DEVICE_A1),
        &challenge_for("challenge-1", DEVICE_A1),
        &proof_for("device-belonging-to-nobody", "challenge-1"),
        device(DEVICE_A1, DeviceLifecycleState::Active),
        policy,
        &verifier,
    );
    if foreign_proof_device.is_ok() {
        ok(
            "PP4",
            "step-up: a proof whose device_id names an unrelated device was ACCEPTED (asserting the current behaviour)",
        );
        defect(
            "DEFECT-15",
            "ExternalStepUpProof.device_id is never compared to anything: validate_step_up_authorization binds the proof by issuer, audience, subject, challenge_id and action, but not by device, so a proof minted for a different device authorizes the step-up",
            "src/app_vault.rs validate_step_up_authorization(): the proof comparison block checks proof.issuer, proof.audience, proof.subject, proof.challenge_id and proof.action and stops; grep -n 'proof.device_id' src/app_vault.rs -> no matches. The SQL half is no better: cliptown.consume_external_step_up() in schema/schema.sql compares proof.proof_id, issuer, subject, audience and action but never joins the proof's approving_external_device_id (the column src/entity/external_step_up_proof.rs declares) to challenge.initiating_device_id. The repository README states the proof is 'bound to one subject, initiating device, challenge, action, method, route, target, body hash, issuer key, and expiration' — the initiating-device half of that claim is unimplemented at both layers. Reproduce: call validate_step_up_authorization with proof.device_id = \"device-belonging-to-nobody\" and every other field consistent -> Ok(ValidatedStepUpConsumption).",
        );
    } else {
        ok(
            "PP4",
            "step-up: a proof naming a foreign device_id is refused (device binding is enforced)",
        );
    }

    // Cross-tenant proof: a proof for a different subject must be refused.
    let mut foreign_subject = proof_for(DEVICE_A1, "challenge-1");
    foreign_subject.subject = "bbbbbbbb-0000-4000-8000-00000000000b".into();
    let cross_subject = validate_step_up_authorization(
        NOW,
        &request_for(DEVICE_A1),
        &challenge_for("challenge-1", DEVICE_A1),
        &foreign_subject,
        device(DEVICE_A1, DeviceLifecycleState::Active),
        policy,
        &verifier,
    );
    if cross_subject.is_err() {
        ok("PP5", "step-up: a proof issued for another subject is refused");
    } else {
        no(
            "PP5",
            "step-up: a proof issued for another subject was accepted",
        );
    }

    // The target-resource binding must not fail open when the field is absent on
    // one side only — an Option comparison is exactly where that goes wrong.
    let mut no_target = challenge_for("challenge-1", DEVICE_A1);
    no_target.target_resource_id = None;
    let target_mismatch = validate_step_up_authorization(
        NOW,
        &request_for(DEVICE_A1), // the request still names device-victim
        &no_target,
        &proof_for(DEVICE_A1, "challenge-1"),
        device(DEVICE_A1, DeviceLifecycleState::Active),
        policy,
        &verifier,
    );
    if target_mismatch.is_err() {
        ok("PP6", "step-up: a challenge with target_resource_id=None does not authorize a request that names a target (the Option mismatch is fail-closed)");
    } else {
        no(
            "PP6",
            "step-up: an absent target_resource_id on the challenge authorized a targeted request",
        );
    }

    // A consumed or invalidated challenge must never be reusable.
    for label in ["consumed", "invalidated"] {
        let mut c = challenge_for("challenge-1", DEVICE_A1);
        if label == "consumed" {
            c.consumed = true;
        } else {
            c.invalidated = true;
        }
        let replay = validate_step_up_authorization(
            NOW,
            &request_for(DEVICE_A1),
            &c,
            &proof_for(DEVICE_A1, "challenge-1"),
            device(DEVICE_A1, DeviceLifecycleState::Active),
            policy,
            &verifier,
        );
        if replay.is_err() {
            ok(
                "PP7",
                &format!("step-up: a {label} challenge cannot be replayed"),
            );
        } else {
            no(
                "PP7",
                &format!("step-up: a {label} challenge was replayed successfully"),
            );
        }
    }
}

// --- idempotency -------------------------------------------------------------

fn idempotency_checks() {
    let existing = IdempotencyBinding {
        subject: "subject-00000001",
        key: "idempotency-key-00000001",
        operation: IdempotentOperation::Create,
        normalized_route: "/v1/integrations/memebank/transfers",
        request_digest: DIGEST,
        expires_at_unix_seconds: NOW + 3600,
    };

    let replay = evaluate_idempotency(
        NOW,
        Some(existing.clone()),
        existing.subject,
        existing.key,
        existing.operation,
        existing.normalized_route,
        existing.request_digest,
    );
    if replay == Ok(IdempotencyDecision::Replay) {
        ok(
            "PP8",
            "idempotency: an identical retry is classified Replay, not a second write",
        );
    } else {
        no("PP8", &format!("idempotency: identical retry returned {replay:?}"));
    }

    let tampered = evaluate_idempotency(
        NOW,
        Some(existing.clone()),
        existing.subject,
        existing.key,
        existing.operation,
        existing.normalized_route,
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    );
    if tampered == Err(TransferError::IdempotencyConflict) {
        ok("PP9", "idempotency: the same key with a different request digest is a conflict, so a key cannot be recycled to smuggle a different body");
    } else {
        no("PP9", &format!("idempotency: digest-swapped retry returned {tampered:?}"));
    }

    let rerouted = evaluate_idempotency(
        NOW,
        Some(existing.clone()),
        existing.subject,
        existing.key,
        IdempotentOperation::Acknowledge,
        "/v1/integrations/memebank/transfers/00000000-0000-4000-8000-000000000002/ack",
        DIGEST,
    );
    if rerouted == Err(TransferError::IdempotencyConflict) {
        ok("PP10", "idempotency: a create key replayed against the acknowledge route is a conflict (route- and operation-bound)");
    } else {
        no("PP10", &format!("idempotency: cross-route replay returned {rerouted:?}"));
    }

    // Cross-subject must read as absent, never as a conflict — a conflict would
    // tell an attacker that some other tenant is holding that key.
    let cross = evaluate_idempotency(
        NOW,
        Some(existing.clone()),
        "another-subject-0001",
        existing.key,
        existing.operation,
        existing.normalized_route,
        existing.request_digest,
    );
    if cross == Ok(IdempotencyDecision::New) {
        ok("PP11", "idempotency: another tenant's record reads as absent rather than as a conflict — no cross-tenant existence oracle");
    } else {
        no("PP11", &format!("idempotency: cross-subject lookup returned {cross:?}, which leaks that the key is taken"));
    }

    let expired = evaluate_idempotency(
        NOW + 7200,
        Some(existing.clone()),
        existing.subject,
        existing.key,
        existing.operation,
        existing.normalized_route,
        existing.request_digest,
    );
    if expired == Ok(IdempotencyDecision::New) {
        ok("PP12", "idempotency: an expired binding stops replaying and becomes New");
    } else {
        no("PP12", &format!("idempotency: expired binding returned {expired:?}"));
    }
}

// --- binary upload / object manifests ----------------------------------------

fn chunk(index: u32, len: u64) -> EncryptedObjectChunk {
    EncryptedObjectChunk {
        chunk_index: index,
        ciphertext_length: len,
        ciphertext_sha256_base64: DIGEST.into(),
        nonce_base64: "AAAAAAAAAAAAAAAAAAAAAAAA".into(),
        randomized_storage_key: format!("randomized/object/chunk-{index}"),
    }
}

fn manifest(
    chunks: Vec<EncryptedObjectChunk>,
    declared_ciphertext_length: u64,
) -> EncryptedObjectManifest {
    EncryptedObjectManifest {
        manifest_id: "manifest-1".into(),
        object_id: "object-1".into(),
        clip_id: "clip-1".into(),
        content_cipher_version: "xchacha20poly1305-chunked-v1".into(),
        plaintext_length: 3_145_728,
        ciphertext_length: declared_ciphertext_length,
        chunk_size: 65_536,
        chunks,
        wrapped_keys: vec![WrappedContentKey {
            recipient_device_id: DEVICE_A1.into(),
            key_id: "key-1".into(),
            algorithm: "signal-envelope-v1".into(),
            nonce_base64: "AAAAAAAAAAAAAAAAAAAAAAAA".into(),
            wrapped_key_base64: "AAAA".into(),
            associated_data_hash_base64: DIGEST.into(),
        }],
        encrypted_metadata: serde_json::json!({"ciphertext": "opaque"}),
        ciphertext_sha256_base64: DIGEST.into(),
    }
}

fn object_checks() {
    let honest = manifest(vec![chunk(0, 65_536), chunk(1, 65_536)], 131_072);
    if honest.validate().is_ok() {
        ok("PP13", "object manifest: a well-formed chunked manifest validates (so the negatives below are not passing vacuously)");
    } else {
        no("PP13", "object manifest: a well-formed manifest was rejected");
    }

    // Non-contiguous chunk indices must be refused — a gap is a hole in the
    // decrypted file.
    let gapped = manifest(vec![chunk(0, 65_536), chunk(2, 65_536)], 131_072);
    if gapped.validate().is_err() {
        ok("PP14", "object manifest: non-contiguous chunk indices are refused");
    } else {
        no("PP14", "object manifest: a manifest with a missing chunk index validated");
    }

    // Path traversal in a storage key must be refused.
    let mut traversal = manifest(vec![chunk(0, 65_536)], 65_536);
    traversal.chunks[0].randomized_storage_key = "../../other-tenant/object/chunk-0".into();
    if traversal.validate().is_err() {
        ok("PP15", "object manifest: a storage key containing .. is refused (no traversal into another tenant's prefix)");
    } else {
        no("PP15", "object manifest: a path-traversing storage key validated");
    }

    // Two wrapped keys for one recipient device must be refused.
    let mut duped = manifest(vec![chunk(0, 65_536)], 65_536);
    let first = duped.wrapped_keys[0].clone();
    duped.wrapped_keys.push(first);
    if duped.validate().is_err() {
        ok("PP16", "object manifest: two wrapped keys for the same recipient device are refused");
    } else {
        no("PP16", "object manifest: duplicate per-device wrapped keys validated");
    }

    // The declared total contradicts the chunks by four orders of magnitude, and
    // the aggregate digest is not a digest at all.
    let mut lying = manifest(vec![chunk(0, 65_536), chunk(1, 65_536)], 999_999_999);
    lying.ciphertext_sha256_base64 = "not-a-digest".into();
    lying.chunks[0].ciphertext_sha256_base64 = "also-not-a-digest".into();
    if lying.validate().is_ok() {
        ok(
            "PP17",
            "object manifest: a manifest declaring 999999999 ciphertext bytes over 131072 bytes of chunks, with 'not-a-digest' as its sha256, was ACCEPTED (asserting the current behaviour)",
        );
        defect(
            "DEFECT-16",
            "EncryptedObjectManifest::validate() does not verify integrity metadata: it never sums chunk lengths against the declared ciphertext_length, and it accepts any non-empty string as a sha256 digest, so a truncated or substituted upload passes validation",
            "src/encrypted_objects.rs EncryptedObjectManifest::validate(): the per-chunk loop tests only chunk.ciphertext_sha256_base64.is_empty(), and no branch reads self.ciphertext_length at all. Reproduce by validating a manifest with ciphertext_length=999999999, chunks=[65536,65536] and ciphertext_sha256_base64=\"not-a-digest\" -> Ok(()). Contrast memebank_transfer::is_sha256_base64url in the same crate, which enforces 43..=44 base64url characters on content_sha256; the object path has no equivalent. The module's own unit test passes ciphertext_sha256_base64: \"aggregate\", so it encodes the gap rather than catching it.",
        );
    } else {
        ok("PP17", "object manifest: a contradictory length and malformed digests are refused");
    }

    // ObjectGrantPolicy declares a 2 GiB ceiling, but validate() takes no policy
    // argument, so nothing ever applies it to a manifest.
    let policy = ObjectGrantPolicy::default();
    let huge = manifest(vec![chunk(0, 65_536)], policy.max_object_bytes * 4);
    if huge.validate().is_ok() {
        ok(
            "PP18",
            &format!(
                "object manifest: a manifest declaring {} bytes validated although ObjectGrantPolicy::default().max_object_bytes is {} (asserting the current behaviour)",
                policy.max_object_bytes * 4,
                policy.max_object_bytes
            ),
        );
        defect(
            "DEFECT-17",
            "ObjectGrantPolicy::max_object_bytes and max_chunks are never enforced against a manifest: EncryptedObjectManifest::validate(&self) takes no policy parameter, so the declared upload ceiling is unreachable code",
            "src/encrypted_objects.rs: `impl EncryptedObjectManifest { pub fn validate(&self) -> Result<(), &'static str> }` has no ObjectGrantPolicy argument, and ObjectGrantPolicy::validate(self) only range-checks the policy's own fields. Reproduce by validating a manifest with ciphertext_length = 4 * ObjectGrantPolicy::default().max_object_bytes -> Ok(()).",
        );
    } else {
        ok("PP18", "object manifest: an oversized manifest is refused against the grant policy");
    }
}

fn main() {
    step_up_checks();
    idempotency_checks();
    object_checks();
}
