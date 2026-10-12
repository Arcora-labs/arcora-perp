//! Test-only signed/sealed channel for caller-owned synthetic fixture peers.
//! A configured software key signs each existing fixture frame; no attestation,
//! real proof, service approval, chain delivery or submission capability is added.
//! Replay memory belongs to one owned session and is neither durable nor global.
use crate::candidate_fixture_transport::{
    decode_request, decode_response, Operation, WireFrame, FRAME_HEADER_BYTES, MAX_FRAME_BYTES,
};
use dark_perp_attestation::{dh_shared, ephemeral_keypair, StaticSecret};
use k256::ecdsa::{
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};

pub(crate) const SEALED_EXCHANGE_PATH: &str = "/candidate-fixture/sealed/v1/exchange";
pub(crate) const SEALED_CONTENT_TYPE: &str = "application/x-arcora-candidate-fixture-sealed-v1";
pub(crate) const SEALED_HEADER_BYTES: usize = 330;
const BOX_OVERHEAD: usize = 1 + 32 + 24 + 16;
const SIGNATURE_BYTES: usize = 64;
pub(crate) const SEALED_OVERHEAD: usize = SEALED_HEADER_BYTES + BOX_OVERHEAD + SIGNATURE_BYTES;
pub(crate) const MIN_SEALED_FRAME: usize = FRAME_HEADER_BYTES + SEALED_OVERHEAD;
pub(crate) const MAX_SEALED_FRAME: usize = MAX_FRAME_BYTES + SEALED_OVERHEAD;
pub(crate) const MAX_REPLAY_CAPACITY: usize = 4096;
const MAGIC: &[u8; 8] = b"DPCFSEA1";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"arcora/candidate-fixture/sealed/v1\0";
const AAD_DOMAIN: u8 = 0xc7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SealError {
    Key,
    Pins,
    Bounds,
    Framing,
    Scope,
    Context,
    Signature,
    Decryption,
    Replay,
    Capacity,
    Poisoned,
    Randomness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FixturePublicKeys {
    pub(crate) signing: [u8; 33],
    pub(crate) x25519: [u8; 32],
}

/// Owned fixture secrets have no serialization, Debug or Clone implementation.
/// This does not promise zeroization of every plaintext/copy elsewhere in the
/// native test process or confidentiality against its owner.
pub(crate) struct FixtureKeys {
    signing: SigningKey,
    x25519: StaticSecret,
    public: FixturePublicKeys,
}
impl FixtureKeys {
    pub(crate) fn from_seed(signing: [u8; 32], x25519: [u8; 32]) -> Result<Self, SealError> {
        let signing = SigningKey::from_slice(&signing).map_err(|_| SealError::Key)?;
        let (x25519, public) = ephemeral_keypair(&x25519);
        let encoded = signing.verifying_key().to_encoded_point(true);
        Ok(Self {
            signing,
            x25519,
            public: FixturePublicKeys {
                signing: encoded.as_bytes().try_into().map_err(|_| SealError::Key)?,
                x25519: public,
            },
        })
    }

    pub(crate) fn random() -> Result<Self, SealError> {
        let mut signing = [0; 32];
        let mut x25519 = [0; 32];
        OsRng
            .try_fill_bytes(&mut signing)
            .map_err(|_| SealError::Randomness)?;
        OsRng
            .try_fill_bytes(&mut x25519)
            .map_err(|_| SealError::Randomness)?;
        Self::from_seed(signing, x25519)
    }

    pub(crate) fn public_keys(&self) -> FixturePublicKeys {
        self.public
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChannelPins {
    pub(crate) session_id: [u8; 32],
    pub(crate) local: FixturePublicKeys,
    pub(crate) remote: FixturePublicKeys,
    pub(crate) request_sha256: [u8; 32],
    pub(crate) program_sha256: [u8; 32],
}
impl ChannelPins {
    pub(crate) fn reverse(&self) -> Self {
        Self {
            local: self.remote,
            remote: self.local,
            ..*self
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Direction {
    Request = 1,
    Response = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FrameContext {
    pub(crate) operation: Operation,
    pub(crate) request_sha256: [u8; 32],
    pub(crate) program_sha256: [u8; 32],
    pub(crate) exchange_id: u64,
    pub(crate) request_payload_sha256: [u8; 32],
    pub(crate) request_payload_len: u32,
}
impl FrameContext {
    pub(crate) fn from_frame(frame: &WireFrame) -> Result<Self, SealError> {
        if frame.exchange_id == 0
            || frame.request_sha256 == [0; 32]
            || frame.program_sha256 == [0; 32]
            || frame.request_payload_len as usize > MAX_FRAME_BYTES - FRAME_HEADER_BYTES
        {
            return Err(SealError::Context);
        }
        Ok(Self {
            operation: frame.operation,
            request_sha256: frame.request_sha256,
            program_sha256: frame.program_sha256,
            exchange_id: frame.exchange_id,
            request_payload_sha256: frame.request_payload_sha256,
            request_payload_len: frame.request_payload_len,
        })
    }
}

pub(crate) fn sealed_wire_bound(inner_bound: usize) -> Result<usize, SealError> {
    if !(FRAME_HEADER_BYTES..=MAX_FRAME_BYTES).contains(&inner_bound) {
        return Err(SealError::Bounds);
    }
    inner_bound
        .checked_add(SEALED_OVERHEAD)
        .ok_or(SealError::Bounds)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn verifying_key(key: &[u8; 33]) -> Result<VerifyingKey, SealError> {
    if !matches!(key[0], 2 | 3) {
        return Err(SealError::Key);
    }
    let parsed = VerifyingKey::from_sec1_bytes(key).map_err(|_| SealError::Key)?;
    if parsed.to_encoded_point(true).as_bytes() != key {
        return Err(SealError::Key);
    }
    Ok(parsed)
}

fn canonical_x25519(key: &[u8; 32]) -> Result<(), SealError> {
    // This fixture format accepts only canonical u-coordinates < 2^255-19.
    // RFC7748 aliases are refused rather than used as distinct identity pins.
    let mut prime = [0xff; 32];
    prime[0] = 0xed;
    prime[31] = 0x7f;
    if key.iter().rev().cmp(prime.iter().rev()) != std::cmp::Ordering::Less {
        return Err(SealError::Key);
    }
    Ok(())
}

fn validate_pins(keys: &FixtureKeys, pins: &ChannelPins) -> Result<(), SealError> {
    if pins.session_id == [0; 32]
        || pins.request_sha256 == [0; 32]
        || pins.program_sha256 == [0; 32]
        || keys.public != pins.local
        || pins.local.signing == pins.remote.signing
        || pins.local.x25519 == pins.remote.x25519
    {
        return Err(SealError::Pins);
    }
    verifying_key(&pins.local.signing)?;
    verifying_key(&pins.remote.signing)?;
    canonical_x25519(&pins.local.x25519)?;
    canonical_x25519(&pins.remote.x25519)?;
    // Existing dalek-backed helper rejects all non-contributory peers; invoking
    // its pure DH operation does not invoke/approve any attestation flow.
    dh_shared(&keys.x25519, &pins.remote.x25519).map_err(|_| SealError::Key)?;
    Ok(())
}

fn decode_inner(inner: &[u8], direction: Direction) -> Result<WireFrame, SealError> {
    match direction {
        Direction::Request => decode_request(inner),
        Direction::Response => decode_response(inner),
    }
    .map_err(|_| SealError::Framing)
}

fn context_matches_pins(context: &FrameContext, pins: &ChannelPins) -> Result<(), SealError> {
    if context.request_sha256 != pins.request_sha256
        || context.program_sha256 != pins.program_sha256
    {
        return Err(SealError::Context);
    }
    Ok(())
}

fn header(
    pins: &ChannelPins,
    direction: Direction,
    context: &FrameContext,
    inner: &[u8],
) -> Result<Vec<u8>, SealError> {
    context_matches_pins(context, pins)?;
    sealed_wire_bound(inner.len())?;
    let mut bytes = Vec::with_capacity(SEALED_HEADER_BYTES);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&[direction as u8, 3, 0, 0, 0, 0]);
    bytes.extend_from_slice(&pins.session_id);
    bytes.extend_from_slice(&pins.local.signing);
    bytes.extend_from_slice(&pins.remote.signing);
    bytes.extend_from_slice(&pins.local.x25519);
    bytes.extend_from_slice(&pins.remote.x25519);
    bytes.extend_from_slice(&context.request_sha256);
    bytes.extend_from_slice(&context.program_sha256);
    bytes.extend_from_slice(&[context.operation as u8, 0, 0, 0]);
    bytes.extend_from_slice(&context.exchange_id.to_be_bytes());
    bytes.extend_from_slice(&context.request_payload_sha256);
    bytes.extend_from_slice(&context.request_payload_len.to_be_bytes());
    bytes.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&sha256(inner));
    bytes.extend_from_slice(&((inner.len() + BOX_OVERHEAD) as u32).to_be_bytes());
    Ok(bytes)
}

fn bound_domain(header: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        DOMAIN.len() + SEALED_EXCHANGE_PATH.len() + SEALED_CONTENT_TYPE.len() + 2 + header.len(),
    );
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(SEALED_EXCHANGE_PATH.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(SEALED_CONTENT_TYPE.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(header);
    bytes
}

fn signature_digest(header: &[u8], sealed: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(bound_domain(header));
    hash.update(sealed);
    hash.finalize().into()
}

/// Seal one exact existing inner frame, without reserving receiver replay state.
/// The receiver must use ReplayReceiver before an effect; open_frame alone is a
/// cryptographic/context decoder and makes no duplicate-admission decision.
pub(crate) fn seal_frame(
    keys: &FixtureKeys,
    pins: &ChannelPins,
    direction: Direction,
    inner: &[u8],
) -> Result<Vec<u8>, SealError> {
    validate_pins(keys, pins)?;
    let context = FrameContext::from_frame(&decode_inner(inner, direction)?)?;
    let header = header(pins, direction, &context, inner)?;
    let aad = sealed_box::domain_aad(AAD_DOMAIN, &bound_domain(&header));
    let sealed = sealed_box::seal(&pins.remote.x25519, inner, &aad, OsRng).to_bytes();
    let signature: Signature = keys
        .signing
        .sign_prehash(&signature_digest(&header, &sealed))
        .map_err(|_| SealError::Signature)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    let mut bytes = Vec::with_capacity(sealed_wire_bound(inner.len())?);
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&sealed);
    bytes.extend_from_slice(&signature.to_bytes());
    Ok(bytes)
}

struct Parsed<'a> {
    context: FrameContext,
    inner_len: usize,
    inner_sha256: [u8; 32],
    header: &'a [u8],
    sealed: &'a [u8],
    signature: &'a [u8],
}

fn parse_outer<'a>(
    pins: &ChannelPins,
    direction: Direction,
    outer: &'a [u8],
) -> Result<Parsed<'a>, SealError> {
    if !(MIN_SEALED_FRAME..=MAX_SEALED_FRAME).contains(&outer.len()) {
        return Err(SealError::Bounds);
    }
    let header = &outer[..SEALED_HEADER_BYTES];
    if &header[..8] != MAGIC
        || u16::from_be_bytes(header[8..10].try_into().unwrap()) != VERSION
        || header[13..16] != [0; 3]
        || header[243..246] != [0; 3]
    {
        return Err(SealError::Framing);
    }
    if header[10] != direction as u8 || header[11] != 3 || header[12] != 0 {
        return Err(SealError::Scope);
    }
    if header[16..48] != pins.session_id
        || header[48..81] != pins.remote.signing
        || header[81..114] != pins.local.signing
        || header[114..146] != pins.remote.x25519
        || header[146..178] != pins.local.x25519
    {
        return Err(SealError::Pins);
    }
    let operation = match header[242] {
        1 => Operation::RegisterClock,
        2 => Operation::LookupClock,
        3 => Operation::RegisterReports,
        4 => Operation::LookupReports,
        5 => Operation::ProveFixture,
        6 => Operation::Recheck,
        7 => Operation::BroadcastFixture,
        8 => Operation::LookupOutcome,
        _ => return Err(SealError::Framing),
    };
    let context = FrameContext {
        operation,
        request_sha256: header[178..210].try_into().unwrap(),
        program_sha256: header[210..242].try_into().unwrap(),
        exchange_id: u64::from_be_bytes(header[246..254].try_into().unwrap()),
        request_payload_sha256: header[254..286].try_into().unwrap(),
        request_payload_len: u32::from_be_bytes(header[286..290].try_into().unwrap()),
    };
    context_matches_pins(&context, pins)?;
    if context.exchange_id == 0
        || context.request_payload_len as usize > MAX_FRAME_BYTES - FRAME_HEADER_BYTES
    {
        return Err(SealError::Context);
    }
    let inner_len = u32::from_be_bytes(header[290..294].try_into().unwrap()) as usize;
    let sealed_len = u32::from_be_bytes(header[326..330].try_into().unwrap()) as usize;
    if sealed_wire_bound(inner_len)? != outer.len() || sealed_len != inner_len + BOX_OVERHEAD {
        return Err(SealError::Bounds);
    }
    Ok(Parsed {
        context,
        inner_len,
        inner_sha256: header[294..326].try_into().unwrap(),
        header,
        sealed: &outer[SEALED_HEADER_BYTES..SEALED_HEADER_BYTES + sealed_len],
        signature: &outer[SEALED_HEADER_BYTES + sealed_len..],
    })
}

/// Verify configured sender signature before box allocation/decryption and inner
/// decoding. Expected context pins the original request when opening a response.
pub(crate) fn open_frame(
    keys: &FixtureKeys,
    pins: &ChannelPins,
    direction: Direction,
    outer: &[u8],
    expected: Option<&FrameContext>,
) -> Result<Vec<u8>, SealError> {
    validate_pins(keys, pins)?;
    let parsed = parse_outer(pins, direction, outer)?;
    if expected.is_some_and(|expected| *expected != parsed.context) {
        return Err(SealError::Context);
    }
    let signature = Signature::from_slice(parsed.signature).map_err(|_| SealError::Signature)?;
    if signature.normalize_s().is_some() {
        return Err(SealError::Signature);
    }
    verifying_key(&pins.remote.signing)?
        .verify_prehash(&signature_digest(parsed.header, parsed.sealed), &signature)
        .map_err(|_| SealError::Signature)?;
    if parsed.sealed[0] != sealed_box::SEALED_BOX_VERSION {
        return Err(SealError::Framing);
    }
    let epk = parsed.sealed[1..33].try_into().unwrap();
    canonical_x25519(&epk)?;
    dh_shared(&keys.x25519, &epk).map_err(|_| SealError::Key)?;
    let sealed = sealed_box::SealedBox::from_bytes(parsed.sealed).ok_or(SealError::Framing)?;
    let aad = sealed_box::domain_aad(AAD_DOMAIN, &bound_domain(parsed.header));
    let inner =
        sealed_box::unseal(&keys.x25519.to_bytes(), &sealed, &aad).ok_or(SealError::Decryption)?;
    if inner.len() != parsed.inner_len || sha256(&inner) != parsed.inner_sha256 {
        return Err(SealError::Context);
    }
    let context = FrameContext::from_frame(&decode_inner(&inner, direction)?)?;
    if context != parsed.context {
        return Err(SealError::Context);
    }
    Ok(inner)
}

type Effect = (u8, [u8; 32], u32);

struct ReplayGuard {
    capacity: usize,
    exchanges: BTreeSet<u64>,
    effects: BTreeSet<Effect>,
}
impl ReplayGuard {
    fn new(capacity: usize) -> Result<Self, SealError> {
        if !(1..=MAX_REPLAY_CAPACITY).contains(&capacity) {
            return Err(SealError::Capacity);
        }
        Ok(Self {
            capacity,
            exchanges: BTreeSet::new(),
            effects: BTreeSet::new(),
        })
    }
    fn reserve(&mut self, context: &FrameContext, mutations: bool) -> Result<(), SealError> {
        let effect = mutations
            .then_some(context.operation)
            .filter(|operation| {
                matches!(
                    operation,
                    Operation::RegisterClock
                        | Operation::RegisterReports
                        | Operation::BroadcastFixture
                )
            })
            .map(|operation| {
                (
                    operation as u8,
                    context.request_payload_sha256,
                    context.request_payload_len,
                )
            });
        if self.exchanges.contains(&context.exchange_id)
            || effect.is_some_and(|effect| self.effects.contains(&effect))
        {
            return Err(SealError::Replay);
        }
        if self.exchanges.len() == self.capacity {
            return Err(SealError::Capacity);
        }
        // All checks precede both insertions: rejected packets consume no slot.
        self.exchanges.insert(context.exchange_id);
        if let Some(effect) = effect {
            self.effects.insert(effect);
        }
        Ok(())
    }
}

/// One server-owned receiver with immutable pins after its first authenticated
/// request. Admission is reserved before returning bytes to a fixture effect.
/// Lost ACK/effect failures retain the reservation; no silent eviction/retry.
pub(crate) struct ReplayReceiver {
    pins: Option<ChannelPins>,
    guard: ReplayGuard,
}
impl ReplayReceiver {
    pub(crate) fn new(capacity: usize) -> Result<Self, SealError> {
        Ok(Self {
            pins: None,
            guard: ReplayGuard::new(capacity)?,
        })
    }
    pub(crate) fn open_request(
        &mut self,
        keys: &FixtureKeys,
        pins: &ChannelPins,
        outer: &[u8],
    ) -> Result<Vec<u8>, SealError> {
        if self.pins.is_some_and(|expected| expected != *pins) {
            return Err(SealError::Pins);
        }
        let inner = open_frame(keys, pins, Direction::Request, outer, None)?;
        let context =
            FrameContext::from_frame(&decode_request(&inner).map_err(|_| SealError::Framing)?)?;
        self.guard.reserve(&context, true)?;
        self.pins = Some(*pins);
        Ok(inner)
    }
}

struct ChannelReplay {
    sent: ReplayGuard,
    sent_contexts: BTreeMap<u64, FrameContext>,
    received: ReplayGuard,
}

/// Client channel owns its keys and bounded replay state; &self supports the
/// existing immutable fixture transport callback API. Poison always refuses.
pub(crate) struct SealedChannel {
    keys: FixtureKeys,
    pins: ChannelPins,
    replay: Mutex<ChannelReplay>,
}
impl SealedChannel {
    pub(crate) fn new(
        keys: FixtureKeys,
        pins: ChannelPins,
        capacity: usize,
    ) -> Result<Self, SealError> {
        validate_pins(&keys, &pins)?;
        Ok(Self {
            keys,
            pins,
            replay: Mutex::new(ChannelReplay {
                sent: ReplayGuard::new(capacity)?,
                sent_contexts: BTreeMap::new(),
                received: ReplayGuard::new(capacity)?,
            }),
        })
    }
    pub(crate) fn pins(&self) -> &ChannelPins {
        &self.pins
    }
    pub(crate) fn matches_request(
        &self,
        request_sha256: &[u8; 32],
        program_sha256: &[u8; 32],
    ) -> bool {
        &self.pins.request_sha256 == request_sha256 && &self.pins.program_sha256 == program_sha256
    }
    pub(crate) fn wrap_request(&self, inner: &[u8]) -> Result<Vec<u8>, SealError> {
        let context =
            FrameContext::from_frame(&decode_request(inner).map_err(|_| SealError::Framing)?)?;
        let outer = seal_frame(&self.keys, &self.pins, Direction::Request, inner)?;
        let mut replay = self.replay.lock().map_err(|_| SealError::Poisoned)?;
        replay.sent.reserve(&context, false)?;
        replay.sent_contexts.insert(context.exchange_id, context);
        Ok(outer)
    }
    pub(crate) fn open_response(
        &self,
        outer: &[u8],
        expected: &WireFrame,
    ) -> Result<Vec<u8>, SealError> {
        let context = FrameContext::from_frame(expected)?;
        let inner = open_frame(
            &self.keys,
            &self.pins,
            Direction::Response,
            outer,
            Some(&context),
        )?;
        let mut replay = self.replay.lock().map_err(|_| SealError::Poisoned)?;
        if replay.sent_contexts.get(&context.exchange_id) != Some(&context) {
            return Err(SealError::Context);
        }
        replay.received.reserve(&context, false)?;
        Ok(inner)
    }
}
