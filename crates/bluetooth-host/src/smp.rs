//! The Security Manager (Core Vol 3, Part H): LE legacy pairing and LE
//! Secure Connections, every association model (Just Works, Numeric
//! Comparison, Passkey Entry, Out of Band), key distribution and bonding,
//! and re-encryption with stored keys.
//!
//! Each connection has one task that owns its SMP channel; a pairing runs
//! inside it as straight-line code, each step waiting (30 s at most) for the
//! peer's next PDU.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bt_hci::cmd::le::{
    LeEnableEncryption, LeLongTermKeyRequestNegativeReply, LeLongTermKeyRequestReply,
};
use bt_hci::param::ConnHandle;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::address::{Address, AddressType};
use crate::connection::{ConnState, Connection, Role, Security};
use crate::crypto::{self, EcdhKey};
use crate::error::{Error, Result};
use crate::host::{Host, HostEvent};
use crate::keys::{Bond, LongTermKey};
use crate::l2cap::cid;

/// SMP opcodes.
mod code {
    pub const PAIRING_REQUEST: u8 = 0x01;
    pub const PAIRING_RESPONSE: u8 = 0x02;
    pub const PAIRING_CONFIRM: u8 = 0x03;
    pub const PAIRING_RANDOM: u8 = 0x04;
    pub const PAIRING_FAILED: u8 = 0x05;
    pub const ENCRYPTION_INFORMATION: u8 = 0x06;
    pub const CENTRAL_IDENTIFICATION: u8 = 0x07;
    pub const IDENTITY_INFORMATION: u8 = 0x08;
    pub const IDENTITY_ADDRESS_INFORMATION: u8 = 0x09;
    pub const SIGNING_INFORMATION: u8 = 0x0a;
    pub const SECURITY_REQUEST: u8 = 0x0b;
    pub const PAIRING_PUBLIC_KEY: u8 = 0x0c;
    pub const PAIRING_DHKEY_CHECK: u8 = 0x0d;
    pub const KEYPRESS_NOTIFICATION: u8 = 0x0e;
}

/// Pairing Failed reasons.
pub mod reason {
    /// Passkey Entry Failed.
    pub const PASSKEY_ENTRY_FAILED: u8 = 0x01;
    /// OOB Not Available.
    pub const OOB_NOT_AVAILABLE: u8 = 0x02;
    /// Authentication Requirements.
    pub const AUTHENTICATION_REQUIREMENTS: u8 = 0x03;
    /// Confirm Value Failed.
    pub const CONFIRM_VALUE_FAILED: u8 = 0x04;
    /// Pairing Not Supported.
    pub const PAIRING_NOT_SUPPORTED: u8 = 0x05;
    /// Encryption Key Size.
    pub const ENCRYPTION_KEY_SIZE: u8 = 0x06;
    /// Command Not Supported.
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    /// Unspecified Reason.
    pub const UNSPECIFIED: u8 = 0x08;
    /// Invalid Parameters.
    pub const INVALID_PARAMETERS: u8 = 0x0a;
    /// DHKey Check Failed.
    pub const DHKEY_CHECK_FAILED: u8 = 0x0b;
    /// Numeric Comparison Failed.
    pub const NUMERIC_COMPARISON_FAILED: u8 = 0x0c;
}

fn reason_name(r: u8) -> &'static str {
    match r {
        0x01 => "Passkey Entry Failed",
        0x02 => "OOB Not Available",
        0x03 => "Authentication Requirements",
        0x04 => "Confirm Value Failed",
        0x05 => "Pairing Not Supported",
        0x06 => "Encryption Key Size",
        0x07 => "Command Not Supported",
        0x08 => "Unspecified Reason",
        0x09 => "Repeated Attempts",
        0x0a => "Invalid Parameters",
        0x0b => "DHKey Check Failed",
        0x0c => "Numeric Comparison Failed",
        0x0d => "BR/EDR pairing in progress",
        0x0e => "Cross-transport Key Derivation/Generation not allowed",
        0x0f => "Key Rejected",
        0x10 => "Busy",
        _ => "Reserved",
    }
}

/// Input and output capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum IoCapability {
    /// Can show six digits.
    DisplayOnly,
    /// Can show six digits and take yes or no.
    DisplayYesNo,
    /// Can take six digits.
    KeyboardOnly,
    /// Neither.
    NoInputNoOutput,
    /// Can show and take digits.
    KeyboardDisplay,
}

impl IoCapability {
    fn wire(self) -> u8 {
        match self {
            IoCapability::DisplayOnly => 0,
            IoCapability::DisplayYesNo => 1,
            IoCapability::KeyboardOnly => 2,
            IoCapability::NoInputNoOutput => 3,
            IoCapability::KeyboardDisplay => 4,
        }
    }

    fn from_wire(v: u8) -> Option<Self> {
        Some(match v {
            0 => IoCapability::DisplayOnly,
            1 => IoCapability::DisplayYesNo,
            2 => IoCapability::KeyboardOnly,
            3 => IoCapability::NoInputNoOutput,
            4 => IoCapability::KeyboardDisplay,
            _ => return None,
        })
    }
}

/// How the two devices authenticate each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// No authentication (no MITM protection).
    JustWorks,
    /// Both show six digits and a person confirms they match (Secure Connections).
    NumericComparison,
    /// The initiator types what the responder shows.
    PasskeyInitiatorInputs,
    /// The responder types what the initiator shows.
    PasskeyResponderInputs,
    /// A person types the same passkey into both.
    PasskeyBothInput,
    /// Data exchanged out of band (NFC, a QR code).
    OutOfBand,
}

/// The association model, Core Vol 3, Part H, 2.3.5.1 (Table 2.8): rows
/// are the responder's capability, columns the initiator's.
pub fn method(init: IoCapability, resp: IoCapability, sc: bool) -> Method {
    use IoCapability::*;
    use Method::*;
    match (resp, init) {
        (NoInputNoOutput, _) | (_, NoInputNoOutput) => JustWorks,
        (DisplayOnly, DisplayOnly | DisplayYesNo) => JustWorks,
        (DisplayOnly, KeyboardOnly | KeyboardDisplay) => PasskeyInitiatorInputs,
        (DisplayYesNo, DisplayOnly) => JustWorks,
        (DisplayYesNo, DisplayYesNo) => {
            if sc {
                NumericComparison
            } else {
                JustWorks
            }
        }
        (DisplayYesNo, KeyboardOnly) => PasskeyInitiatorInputs,
        (DisplayYesNo, KeyboardDisplay) => {
            if sc {
                NumericComparison
            } else {
                PasskeyInitiatorInputs
            }
        }
        (KeyboardOnly, KeyboardOnly) => PasskeyBothInput,
        (KeyboardOnly, _) => PasskeyResponderInputs,
        (KeyboardDisplay, DisplayOnly) => PasskeyResponderInputs,
        (KeyboardDisplay, DisplayYesNo) => {
            if sc {
                NumericComparison
            } else {
                PasskeyResponderInputs
            }
        }
        (KeyboardDisplay, KeyboardOnly) => PasskeyInitiatorInputs,
        (KeyboardDisplay, KeyboardDisplay) => {
            if sc {
                NumericComparison
            } else {
                PasskeyInitiatorInputs
            }
        }
    }
}

/// Out-of-band data received from a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OobData {
    /// Legacy pairing's temporary key.
    Legacy([u8; 16]),
    /// Secure Connections: the peer's random value and confirm value.
    SecureConnections {
        /// r.
        random: u128,
        /// C = f4(PK, PK, r, 0).
        confirm: u128,
    },
}

/// A boxed future, so [`Agent`] stays object safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Answers the questions pairing asks of a person. The bridge implements
/// it over MQTT; tests implement it with fixed answers.
pub trait Agent: Send + Sync {
    /// A peer asks to pair with this method; return false to refuse.
    fn accept(&self, peer: Address, method: Method) -> BoxFuture<'_, bool>;
    /// Show this passkey (the peer types it).
    fn display_passkey(&self, peer: Address, passkey: u32) -> BoxFuture<'_, ()>;
    /// Type the passkey the peer shows; `None` cancels.
    fn request_passkey(&self, peer: Address) -> BoxFuture<'_, Option<u32>>;
    /// Do both devices show this number?
    fn confirm_number(&self, peer: Address, number: u32) -> BoxFuture<'_, bool>;
    /// The peer's out-of-band data, if any was received.
    fn oob_data(&self, peer: Address) -> BoxFuture<'_, Option<OobData>>;
}

/// An agent for a device with no person at it: accepts Just Works and
/// Numeric Comparison, refuses anything needing a passkey or OOB data.
pub struct AutoAgent;

impl Agent for AutoAgent {
    fn accept(&self, _peer: Address, m: Method) -> BoxFuture<'_, bool> {
        Box::pin(async move { matches!(m, Method::JustWorks | Method::NumericComparison) })
    }
    fn display_passkey(&self, peer: Address, passkey: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move { tracing::info!("pairing with {peer}: passkey {passkey:06}") })
    }
    fn request_passkey(&self, _peer: Address) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async { None })
    }
    fn confirm_number(&self, _peer: Address, _n: u32) -> BoxFuture<'_, bool> {
        Box::pin(async { true })
    }
    fn oob_data(&self, _peer: Address) -> BoxFuture<'_, Option<OobData>> {
        Box::pin(async { None })
    }
}

/// An agent with fixed answers: a passkey to show and to type, whether to
/// confirm numbers, and OOB data.
#[derive(Debug, Clone, Default)]
pub struct FixedAgent {
    /// The passkey shown and typed (0 to 999999); `None` refuses passkey entry.
    pub passkey: Option<u32>,
    /// Answer to numeric comparison.
    pub confirm: bool,
    /// OOB data to use.
    pub oob: Option<OobData>,
}

impl Agent for FixedAgent {
    fn accept(&self, _peer: Address, _m: Method) -> BoxFuture<'_, bool> {
        Box::pin(async { true })
    }
    fn display_passkey(&self, peer: Address, passkey: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move { tracing::info!("pairing with {peer}: passkey {passkey:06}") })
    }
    fn request_passkey(&self, _peer: Address) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async move { self.passkey })
    }
    fn confirm_number(&self, _peer: Address, _n: u32) -> BoxFuture<'_, bool> {
        Box::pin(async move { self.confirm })
    }
    fn oob_data(&self, _peer: Address) -> BoxFuture<'_, Option<OobData>> {
        Box::pin(async move { self.oob })
    }
}

/// Requests to a connection's SMP task.
pub(crate) enum Command {
    Pair(oneshot::Sender<Result<Security>>),
}

const SMP_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_KEY_SIZE: u8 = 7;

/// Key distribution bits.
const KEY_ENC: u8 = 0x01;
const KEY_ID: u8 = 0x02;
const KEY_SIGN: u8 = 0x04;

/// AuthReq bits.
const AUTH_BOND: u8 = 0x01;
const AUTH_MITM: u8 = 0x04;
const AUTH_SC: u8 = 0x08;
const AUTH_CT2: u8 = 0x20;

#[derive(Debug, Clone, Copy)]
struct Features {
    io: u8,
    oob: u8,
    auth: u8,
    max_key: u8,
    init_keys: u8,
    resp_keys: u8,
}

impl Features {
    fn pdu(&self, opcode: u8) -> [u8; 7] {
        [
            opcode,
            self.io,
            self.oob,
            self.auth,
            self.max_key,
            self.init_keys,
            self.resp_keys,
        ]
    }

    fn parse(p: &[u8]) -> Option<Features> {
        let p: &[u8; 7] = p.try_into().ok()?;
        IoCapability::from_wire(p[1])?;
        if !(MIN_KEY_SIZE..=16).contains(&p[4]) {
            return None;
        }
        Some(Features {
            io: p[1],
            oob: p[2],
            auth: p[3],
            max_key: p[4],
            init_keys: p[5] & 0x0f,
            resp_keys: p[6] & 0x0f,
        })
    }
}

/// Parses a Pairing Request or Response PDU (the fuzz targets).
#[cfg(feature = "fuzzing")]
pub(crate) fn parse_features(p: &[u8]) -> bool {
    Features::parse(p).is_some()
}

/// Everything a pairing knows; one per attempt.
struct Pairing<'a> {
    host: &'a Host,
    conn: &'a Arc<ConnState>,
    rx: &'a mut mpsc::Receiver<Vec<u8>>,
    initiator: bool,
    preq: [u8; 7],
    pres: [u8; 7],
    ours: Features,
    theirs: Features,
}

/// The addresses used on the air: (initiator type, initiator, responder type, responder).
fn addresses(host: &Host, conn: &ConnState) -> (u8, [u8; 6], u8, [u8; 6]) {
    let local = host.address();
    let peer = conn.peer;
    match conn.role {
        Role::Central => (local.hci_type(), local.bytes, peer.hci_type(), peer.bytes),
        Role::Peripheral => (peer.hci_type(), peer.bytes, local.hci_type(), local.bytes),
    }
}

impl Pairing<'_> {
    async fn send(&self, pdu: &[u8]) -> Result<()> {
        self.conn.send(self.host, cid::SMP, pdu).await
    }

    /// The next SMP PDU with opcode `want`; Pairing Failed and anything
    /// else end the pairing.
    async fn expect(&mut self, want: u8) -> Result<Vec<u8>> {
        loop {
            let pdu = tokio::select! {
                p = tokio::time::timeout(SMP_TIMEOUT, self.rx.recv()) => match p {
                    Ok(Some(p)) => p,
                    Ok(None) => return Err(Error::Disconnected),
                    Err(_) => return Err(Error::Pairing("the peer stopped answering (SMP timeout)".into())),
                },
                _ = self.conn.wait_closed() => return Err(Error::Disconnected),
            };
            match pdu.first().copied() {
                Some(c) if c == want => return Ok(pdu),
                Some(code::PAIRING_FAILED) => {
                    let r = pdu.get(1).copied().unwrap_or(0);
                    return Err(Error::Pairing(format!(
                        "the peer failed it: {}",
                        reason_name(r)
                    )));
                }
                // Keypress notifications only say a key was pressed.
                Some(code::KEYPRESS_NOTIFICATION) => continue,
                Some(code::SECURITY_REQUEST) => continue,
                _ => {
                    self.fail(reason::UNSPECIFIED).await;
                    return Err(Error::Pairing(format!(
                        "unexpected SMP PDU {:02x?}",
                        pdu.first()
                    )));
                }
            }
        }
    }

    async fn fail(&self, r: u8) {
        let _ = self.send(&[code::PAIRING_FAILED, r]).await;
    }

    async fn failed<T>(&self, r: u8, msg: &str) -> Result<T> {
        self.fail(r).await;
        Err(Error::Pairing(format!("{msg} ({})", reason_name(r))))
    }

    fn peer(&self) -> Address {
        self.conn.identity()
    }

    fn key_size(&self) -> u8 {
        self.ours.max_key.min(self.theirs.max_key)
    }

    fn init_io(&self) -> IoCapability {
        let io = if self.initiator {
            self.ours.io
        } else {
            self.theirs.io
        };
        IoCapability::from_wire(io).unwrap_or(IoCapability::NoInputNoOutput)
    }

    fn resp_io(&self) -> IoCapability {
        let io = if self.initiator {
            self.theirs.io
        } else {
            self.ours.io
        };
        IoCapability::from_wire(io).unwrap_or(IoCapability::NoInputNoOutput)
    }

    /// Runs phases 2 and 3 once the features are exchanged.
    async fn run(mut self) -> Result<Security> {
        let config = &self.host.inner.config;
        let sc = self.ours.auth & self.theirs.auth & AUTH_SC != 0;
        let mitm = (self.ours.auth | self.theirs.auth) & AUTH_MITM != 0;
        if !sc && config.secure_connections_only {
            return self
                .failed(
                    reason::AUTHENTICATION_REQUIREMENTS,
                    "the peer does not do Secure Connections",
                )
                .await;
        }
        let oob = if sc {
            self.ours.oob != 0 || self.theirs.oob != 0
        } else {
            self.ours.oob != 0 && self.theirs.oob != 0
        };
        let m = if oob {
            Method::OutOfBand
        } else if !mitm {
            Method::JustWorks
        } else {
            method(self.init_io(), self.resp_io(), sc)
        };
        if config.mitm && m == Method::JustWorks {
            return self
                .failed(
                    reason::AUTHENTICATION_REQUIREMENTS,
                    "MITM protection is required",
                )
                .await;
        }
        let key_size = self.key_size();
        tracing::info!(
            "pairing with {} ({}, {:?}, {key_size}-octet key)",
            self.peer(),
            if sc { "Secure Connections" } else { "legacy" },
            m
        );
        let (key, authenticated) = if sc {
            (self.secure_connections(m).await?, m != Method::JustWorks)
        } else {
            (self.legacy(m).await?, m != Method::JustWorks)
        };
        let key = mask(key, key_size);
        let security = Security {
            encrypted: true,
            authenticated,
            secure_connections: sc,
            key_size,
            bonded: false,
        };
        // Encrypt the link with the new key.
        self.encrypt_with(key, 0, 0, security).await?;
        // Phase 3: distribute keys over the encrypted link.
        let bonded = self.distribute(sc, key, security).await?;
        let security = Security { bonded, ..security };
        self.conn.security.send_replace(Security {
            encrypted: true,
            ..security
        });
        Ok(security)
    }

    async fn encrypt_with(
        &self,
        key: u128,
        ediv: u16,
        rand: u64,
        security: Security,
    ) -> Result<()> {
        *self
            .conn
            .pairing_key
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some((key, security));
        let (tx, rx) = oneshot::channel();
        self.conn.waiters().encryption = Some(tx);
        if self.initiator {
            self.host
                .inner
                .hci
                .exec_async(&LeEnableEncryption::new(
                    ConnHandle::new(self.conn.handle),
                    rand.to_le_bytes(),
                    ediv,
                    crypto::le(key),
                ))
                .await?;
        }
        // The responder's controller asks for the key (LTK Request), answered
        // from `pairing_key`.
        match tokio::time::timeout(SMP_TIMEOUT, rx).await {
            Ok(Ok(0)) => {
                self.conn.security.send_replace(security);
                Ok(())
            }
            Ok(Ok(s)) => Err(Error::Pairing(format!(
                "encryption failed: {}",
                crate::error::status_name(s)
            ))),
            Ok(Err(_)) => Err(Error::Disconnected),
            Err(_) => Err(Error::Pairing("encryption did not start".into())),
        }
    }

    // ----- LE legacy pairing -----

    async fn legacy(&mut self, m: Method) -> Result<u128> {
        let agent = self.host.inner.config.agent.clone();
        let tk: u128 = match m {
            Method::JustWorks => 0,
            Method::OutOfBand => match agent.oob_data(self.peer()).await {
                Some(OobData::Legacy(tk)) => crypto::from_le(tk),
                _ => return self.failed(reason::OOB_NOT_AVAILABLE, "no OOB data").await,
            },
            _ => u128::from(self.passkey(m).await?),
        };
        let (iat, ia, rat, ra) = addresses(self.host, self.conn);
        let mrand_or_srand = crypto::random_u128();
        let our_confirm = crypto::c1(
            tk,
            mrand_or_srand,
            &self.preq,
            &self.pres,
            iat,
            rat,
            &ia,
            &ra,
        );
        let (mrand, srand) = if self.initiator {
            self.send(&confirm_pdu(code::PAIRING_CONFIRM, our_confirm))
                .await?;
            let sconfirm = value(&self.expect(code::PAIRING_CONFIRM).await?);
            self.send(&confirm_pdu(code::PAIRING_RANDOM, mrand_or_srand))
                .await?;
            let srand = value(&self.expect(code::PAIRING_RANDOM).await?);
            if crypto::c1(tk, srand, &self.preq, &self.pres, iat, rat, &ia, &ra) != sconfirm {
                return self
                    .failed(
                        reason::CONFIRM_VALUE_FAILED,
                        "the peer's confirm value is wrong",
                    )
                    .await;
            }
            (mrand_or_srand, srand)
        } else {
            let mconfirm = value(&self.expect(code::PAIRING_CONFIRM).await?);
            self.send(&confirm_pdu(code::PAIRING_CONFIRM, our_confirm))
                .await?;
            let mrand = value(&self.expect(code::PAIRING_RANDOM).await?);
            if crypto::c1(tk, mrand, &self.preq, &self.pres, iat, rat, &ia, &ra) != mconfirm {
                return self
                    .failed(
                        reason::CONFIRM_VALUE_FAILED,
                        "the peer's confirm value is wrong",
                    )
                    .await;
            }
            self.send(&confirm_pdu(code::PAIRING_RANDOM, mrand_or_srand))
                .await?;
            (mrand, mrand_or_srand)
        };
        Ok(crypto::s1(tk, srand, mrand))
    }

    /// The passkey for this method: shown by us, or typed in.
    async fn passkey(&self, m: Method) -> Result<u32> {
        let agent = self.host.inner.config.agent.clone();
        let we_input = matches!(
            (m, self.initiator),
            (Method::PasskeyInitiatorInputs, true)
                | (Method::PasskeyResponderInputs, false)
                | (Method::PasskeyBothInput, _)
        );
        if we_input {
            match agent.request_passkey(self.peer()).await {
                Some(p) if p <= 999_999 => Ok(p),
                _ => {
                    self.failed(reason::PASSKEY_ENTRY_FAILED, "no passkey entered")
                        .await
                }
            }
        } else {
            // A fixed passkey from the agent if it has one (it may be printed
            // on a label), otherwise a random one.
            let p = match agent.request_passkey(self.peer()).await {
                Some(p) if p <= 999_999 => p,
                _ => {
                    let mut b = [0u8; 4];
                    crypto::random_bytes(&mut b);
                    u32::from_le_bytes(b) % 1_000_000
                }
            };
            agent.display_passkey(self.peer(), p).await;
            Ok(p)
        }
    }

    // ----- LE Secure Connections -----

    async fn secure_connections(&mut self, m: Method) -> Result<u128> {
        let config = &self.host.inner.config;
        let agent = config.agent.clone();
        let local = EcdhKey::generate();
        let pk = |k: &EcdhKey| {
            let mut v = vec![code::PAIRING_PUBLIC_KEY];
            v.extend(k.x.iter().rev());
            v.extend(k.y.iter().rev());
            v
        };
        // Public keys: the initiator's first.
        let theirs = if self.initiator {
            self.send(&pk(&local)).await?;
            self.expect(code::PAIRING_PUBLIC_KEY).await?
        } else {
            let t = self.expect(code::PAIRING_PUBLIC_KEY).await?;
            self.send(&pk(&local)).await?;
            t
        };
        if theirs.len() != 65 {
            return self
                .failed(reason::INVALID_PARAMETERS, "malformed public key")
                .await;
        }
        let mut px = [0u8; 32];
        let mut py = [0u8; 32];
        px.copy_from_slice(&theirs[1..33]);
        py.copy_from_slice(&theirs[33..65]);
        px.reverse();
        py.reverse();
        if px == crypto::DEBUG_PUBLIC_X && !config.allow_debug_keys {
            return self
                .failed(
                    reason::AUTHENTICATION_REQUIREMENTS,
                    "the peer uses the debug key",
                )
                .await;
        }
        if px == local.x {
            // A reflected key would let an attacker complete the exchange.
            return self
                .failed(
                    reason::INVALID_PARAMETERS,
                    "the peer sent our own public key",
                )
                .await;
        }
        let Some(dh) = local.dh_key(&px, &py) else {
            return self
                .failed(
                    reason::DHKEY_CHECK_FAILED,
                    "the peer's public key is not on the curve",
                )
                .await;
        };
        let (pka, pkb) = if self.initiator {
            (local.x, px)
        } else {
            (px, local.x)
        };

        // Authentication stage 1.
        let (na, nb, ra, rb) = match m {
            Method::JustWorks | Method::NumericComparison => {
                let n = crypto::random_u128();
                let (na, nb) = if self.initiator {
                    let cb = value(&self.expect(code::PAIRING_CONFIRM).await?);
                    self.send(&confirm_pdu(code::PAIRING_RANDOM, n)).await?;
                    let nb = value(&self.expect(code::PAIRING_RANDOM).await?);
                    if crypto::f4(&pkb, &pka, nb, 0) != cb {
                        return self
                            .failed(
                                reason::CONFIRM_VALUE_FAILED,
                                "the peer's confirm value is wrong",
                            )
                            .await;
                    }
                    (n, nb)
                } else {
                    self.send(&confirm_pdu(
                        code::PAIRING_CONFIRM,
                        crypto::f4(&pkb, &pka, n, 0),
                    ))
                    .await?;
                    let na = value(&self.expect(code::PAIRING_RANDOM).await?);
                    self.send(&confirm_pdu(code::PAIRING_RANDOM, n)).await?;
                    (na, n)
                };
                if m == Method::NumericComparison {
                    let v = crypto::g2(&pka, &pkb, na, nb) % 1_000_000;
                    if !agent.confirm_number(self.peer(), v).await {
                        return self
                            .failed(
                                reason::NUMERIC_COMPARISON_FAILED,
                                "the numbers were not confirmed",
                            )
                            .await;
                    }
                } else if !self.initiator && !agent.accept(self.peer(), m).await {
                    return self.failed(reason::PAIRING_NOT_SUPPORTED, "refused").await;
                }
                (na, nb, 0, 0)
            }
            Method::OutOfBand => {
                // r for each side: ours if we sent OOB data (none here: we do
                // not generate it), theirs if we received it.
                let peer_oob = match agent.oob_data(self.peer()).await {
                    Some(OobData::SecureConnections { random, confirm }) => Some((random, confirm)),
                    _ => None,
                };
                let we_have_theirs = self.ours.oob != 0;
                let r_peer = match (we_have_theirs, peer_oob) {
                    (true, Some((r, c))) => {
                        let peer_pk = if self.initiator { &pkb } else { &pka };
                        if crypto::f4(peer_pk, peer_pk, r, 0) != c {
                            return self
                                .failed(
                                    reason::CONFIRM_VALUE_FAILED,
                                    "the OOB confirm value is wrong",
                                )
                                .await;
                        }
                        r
                    }
                    (true, None) => {
                        return self.failed(reason::OOB_NOT_AVAILABLE, "no OOB data").await
                    }
                    (false, _) => 0,
                };
                let n = crypto::random_u128();
                let (na, nb) = if self.initiator {
                    self.send(&confirm_pdu(code::PAIRING_RANDOM, n)).await?;
                    (n, value(&self.expect(code::PAIRING_RANDOM).await?))
                } else {
                    let na = value(&self.expect(code::PAIRING_RANDOM).await?);
                    self.send(&confirm_pdu(code::PAIRING_RANDOM, n)).await?;
                    (na, n)
                };
                // ra is the initiator's r (known to the responder), rb the responder's.
                let (ra, rb) = if self.initiator {
                    (0, r_peer)
                } else {
                    (r_peer, 0)
                };
                (na, nb, ra, rb)
            }
            _ => {
                let passkey = self.passkey(m).await?;
                let mut last = (0, 0);
                for i in 0..20 {
                    let bit = 0x80 | ((passkey >> i) & 1) as u8;
                    let n = crypto::random_u128();
                    if self.initiator {
                        self.send(&confirm_pdu(
                            code::PAIRING_CONFIRM,
                            crypto::f4(&pka, &pkb, n, bit),
                        ))
                        .await?;
                        let cb = value(&self.expect(code::PAIRING_CONFIRM).await?);
                        self.send(&confirm_pdu(code::PAIRING_RANDOM, n)).await?;
                        let nb = value(&self.expect(code::PAIRING_RANDOM).await?);
                        if crypto::f4(&pkb, &pka, nb, bit) != cb {
                            return self
                                .failed(reason::CONFIRM_VALUE_FAILED, "passkey round failed")
                                .await;
                        }
                        last = (n, nb);
                    } else {
                        let ca = value(&self.expect(code::PAIRING_CONFIRM).await?);
                        self.send(&confirm_pdu(
                            code::PAIRING_CONFIRM,
                            crypto::f4(&pkb, &pka, n, bit),
                        ))
                        .await?;
                        let na = value(&self.expect(code::PAIRING_RANDOM).await?);
                        if crypto::f4(&pka, &pkb, na, bit) != ca {
                            return self
                                .failed(reason::CONFIRM_VALUE_FAILED, "passkey round failed")
                                .await;
                        }
                        self.send(&confirm_pdu(code::PAIRING_RANDOM, n)).await?;
                        last = (na, n);
                    }
                }
                let r = u128::from(passkey);
                (last.0, last.1, r, r)
            }
        };

        // Authentication stage 2: the DHKey checks.
        let (iat, ia, rat, ra_addr) = addresses(self.host, self.conn);
        let a = crypto::addr56(iat, &ia);
        let b = crypto::addr56(rat, &ra_addr);
        let (mac_key, ltk) = crypto::f5(&dh, na, nb, &a, &b);
        let (init, resp) = if self.initiator {
            (self.ours, self.theirs)
        } else {
            (self.theirs, self.ours)
        };
        let io_a = [init.auth, init.oob, init.io];
        let io_b = [resp.auth, resp.oob, resp.io];
        let ea = crypto::f6(mac_key, na, nb, rb, &io_a, &a, &b);
        let eb = crypto::f6(mac_key, nb, na, ra, &io_b, &b, &a);
        if self.initiator {
            self.send(&confirm_pdu(code::PAIRING_DHKEY_CHECK, ea))
                .await?;
            if value(&self.expect(code::PAIRING_DHKEY_CHECK).await?) != eb {
                return self
                    .failed(
                        reason::DHKEY_CHECK_FAILED,
                        "the peer's DHKey check is wrong",
                    )
                    .await;
            }
        } else {
            if value(&self.expect(code::PAIRING_DHKEY_CHECK).await?) != ea {
                return self
                    .failed(
                        reason::DHKEY_CHECK_FAILED,
                        "the peer's DHKey check is wrong",
                    )
                    .await;
            }
            self.send(&confirm_pdu(code::PAIRING_DHKEY_CHECK, eb))
                .await?;
        }
        Ok(ltk)
    }

    // ----- Phase 3 -----

    /// Exchanges keys (the responder's first); stores the bond. Returns
    /// whether a bond was stored.
    async fn distribute(&mut self, sc: bool, ltk: u128, security: Security) -> Result<bool> {
        let (init, resp) = if self.initiator {
            (self.ours, self.theirs)
        } else {
            (self.theirs, self.ours)
        };
        // Agreed distribution is what both asked for (the response's bits).
        let (resp_keys, init_keys) = (resp.resp_keys, resp.init_keys);
        let (ours_bits, theirs_bits) = if self.initiator {
            (init_keys, resp_keys)
        } else {
            (resp_keys, init_keys)
        };
        let bonding = init.auth & resp.auth & AUTH_BOND != 0 && self.host.inner.config.bonding;
        let mut bond = Bond::new(self.conn.peer);
        bond.authenticated = security.authenticated;
        bond.secure_connections = sc;
        if sc {
            bond.ltk = Some(LongTermKey {
                key: ltk,
                ediv: 0,
                rand: 0,
                key_size: security.key_size,
            });
        }
        if self.initiator {
            self.receive_keys(theirs_bits, sc, &mut bond, security)
                .await?;
            self.send_keys(ours_bits, sc, &mut bond, security).await?;
        } else {
            self.send_keys(ours_bits, sc, &mut bond, security).await?;
            self.receive_keys(theirs_bits, sc, &mut bond, security)
                .await?;
        }
        if bond.identity != self.conn.peer && !self.conn.peer.is_resolvable() {
            bond.aliases.push(self.conn.peer);
        }
        self.conn.set_identity(bond.identity);
        if bonding {
            bond.cccd = self.host.inner.gatt.subscriptions_of(self.conn.handle);
            self.host.inner.keys.store(bond)?;
        }
        Ok(bonding)
    }

    async fn send_keys(
        &self,
        bits: u8,
        sc: bool,
        bond: &mut Bond,
        security: Security,
    ) -> Result<()> {
        if bits & KEY_ENC != 0 && !sc {
            let key = mask(crypto::random_u128(), security.key_size);
            let mut r = [0u8; 10];
            crypto::random_bytes(&mut r);
            let ediv = u16::from_le_bytes([r[0], r[1]]);
            let rand = u64::from_le_bytes([r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]]);
            self.send(&confirm_pdu(code::ENCRYPTION_INFORMATION, key))
                .await?;
            let mut ci = vec![code::CENTRAL_IDENTIFICATION];
            ci.extend_from_slice(&ediv.to_le_bytes());
            ci.extend_from_slice(&rand.to_le_bytes());
            self.send(&ci).await?;
            bond.local_ltk = Some(LongTermKey {
                key,
                ediv,
                rand,
                key_size: security.key_size,
            });
        }
        if bits & KEY_ID != 0 {
            self.send(&confirm_pdu(
                code::IDENTITY_INFORMATION,
                self.host.inner.keys.local_irk(),
            ))
            .await?;
            let me = self.host.address();
            let mut ia = vec![code::IDENTITY_ADDRESS_INFORMATION, me.hci_type()];
            ia.extend_from_slice(&me.bytes);
            self.send(&ia).await?;
        }
        if bits & KEY_SIGN != 0 {
            self.send(&confirm_pdu(
                code::SIGNING_INFORMATION,
                crypto::random_u128(),
            ))
            .await?;
        }
        Ok(())
    }

    async fn receive_keys(
        &mut self,
        bits: u8,
        sc: bool,
        bond: &mut Bond,
        security: Security,
    ) -> Result<()> {
        if bits & KEY_ENC != 0 && !sc {
            let key = value(&self.expect(code::ENCRYPTION_INFORMATION).await?);
            let ci = self.expect(code::CENTRAL_IDENTIFICATION).await?;
            if ci.len() != 11 {
                return self
                    .failed(
                        reason::INVALID_PARAMETERS,
                        "malformed Central Identification",
                    )
                    .await;
            }
            bond.ltk = Some(LongTermKey {
                key,
                ediv: u16::from_le_bytes([ci[1], ci[2]]),
                rand: u64::from_le_bytes(ci[3..11].try_into().unwrap_or([0; 8])),
                key_size: security.key_size,
            });
        }
        if bits & KEY_ID != 0 {
            let irk = value(&self.expect(code::IDENTITY_INFORMATION).await?);
            let ia = self.expect(code::IDENTITY_ADDRESS_INFORMATION).await?;
            if ia.len() != 8 {
                return self
                    .failed(
                        reason::INVALID_PARAMETERS,
                        "malformed Identity Address Information",
                    )
                    .await;
            }
            let addr = Address::from_hci(ia[1], ia[2..8].try_into().unwrap_or([0; 6]));
            if addr.kind == AddressType::Random
                && addr.random_kind() != Some(crate::address::RandomKind::Static)
            {
                return self
                    .failed(
                        reason::INVALID_PARAMETERS,
                        "the identity address is not static",
                    )
                    .await;
            }
            bond.identity = addr;
            // An all-zero IRK means the device does not use private addresses.
            bond.irk = (irk != 0).then_some(irk);
        }
        if bits & KEY_SIGN != 0 {
            bond.csrk = Some(value(&self.expect(code::SIGNING_INFORMATION).await?));
        }
        Ok(())
    }
}

fn mask(key: u128, size: u8) -> u128 {
    if size >= 16 {
        key
    } else {
        key & ((1u128 << (8 * u32::from(size))) - 1)
    }
}

fn confirm_pdu(opcode: u8, v: u128) -> Vec<u8> {
    let mut p = vec![opcode];
    p.extend_from_slice(&crypto::le(v));
    p
}

/// The 128-bit value in a Confirm, Random, key or check PDU (0 if short).
fn value(pdu: &[u8]) -> u128 {
    pdu.get(1..17)
        .and_then(|s| <[u8; 16]>::try_from(s).ok())
        .map(crypto::from_le)
        .unwrap_or(0)
}

/// What we ask for. The OOB flag says whether we hold OOB data from this peer.
async fn local_features(host: &Host, peer: Address) -> Features {
    let c = &host.inner.config;
    let keys = KEY_ENC | KEY_ID;
    let oob = c.agent.oob_data(peer).await.is_some();
    Features {
        io: c.io_capability.wire(),
        oob: u8::from(oob),
        auth: (if c.bonding { AUTH_BOND } else { 0 })
            | (if c.mitm { AUTH_MITM } else { 0 })
            | AUTH_SC
            | AUTH_CT2,
        max_key: 16,
        init_keys: keys,
        resp_keys: keys,
    }
}

/// The SMP task of one connection.
pub(crate) async fn run(
    host: Host,
    conn: Arc<ConnState>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    mut cmds: mpsc::Receiver<Command>,
) {
    loop {
        tokio::select! {
            p = rx.recv() => {
                let Some(pdu) = p else { return };
                on_idle_pdu(&host, &conn, &mut rx, pdu).await;
            }
            c = cmds.recv() => {
                let Some(Command::Pair(reply)) = c else { return };
                let r = initiate(&host, &conn, &mut rx).await;
                report(&host, &conn, &r);
                let _ = reply.send(r);
            }
            _ = conn.wait_closed() => return,
        }
    }
}

fn report(host: &Host, conn: &ConnState, r: &Result<Security>) {
    match r {
        Ok(s) => host.emit(HostEvent::Paired {
            handle: conn.handle,
            identity: conn.identity(),
            bonded: s.bonded,
            security: *s,
        }),
        Err(e) => {
            tracing::info!("pairing on {:#05x} failed: {e}", conn.handle);
            host.emit(HostEvent::PairingFailed {
                handle: conn.handle,
                reason: e.to_string(),
            })
        }
    }
}

/// A PDU outside a pairing: a Pairing Request (we are the responder) or a
/// Security Request (we are central).
async fn on_idle_pdu(
    host: &Host,
    conn: &Arc<ConnState>,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    pdu: Vec<u8>,
) {
    match pdu.first().copied() {
        Some(code::PAIRING_REQUEST) if conn.role == Role::Peripheral => {
            let r = respond(host, conn, rx, &pdu).await;
            report(host, conn, &r);
        }
        Some(code::SECURITY_REQUEST) if conn.role == Role::Central => {
            let _one = conn.security_op.lock().await;
            if conn.security.borrow().encrypted {
                return; // Already done (we may have started it ourselves).
            }
            // Encrypt with the bond's key if there is one, else pair.
            let r = match encrypt_with_bond(host, conn).await {
                Ok(Some(s)) => Ok(s),
                _ => {
                    let r = initiate(host, conn, rx).await;
                    report(host, conn, &r);
                    r
                }
            };
            if let Err(e) = r {
                tracing::info!("security request on {:#05x}: {e}", conn.handle);
            }
        }
        Some(code::PAIRING_FAILED) | Some(code::KEYPRESS_NOTIFICATION) => {}
        Some(_) => {
            let _ = conn
                .send(
                    host,
                    cid::SMP,
                    &[code::PAIRING_FAILED, reason::COMMAND_NOT_SUPPORTED],
                )
                .await;
        }
        None => {}
    }
}

/// Pairs as initiator (central).
async fn initiate(
    host: &Host,
    conn: &Arc<ConnState>,
    rx: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<Security> {
    let ours = local_features(host, conn.identity()).await;
    let preq = ours.pdu(code::PAIRING_REQUEST);
    conn.send(host, cid::SMP, &preq).await?;
    let mut p = Pairing {
        host,
        conn,
        rx,
        initiator: true,
        preq,
        pres: [0; 7],
        ours,
        theirs: ours,
    };
    let rsp = p.expect(code::PAIRING_RESPONSE).await?;
    let Some(theirs) = Features::parse(&rsp) else {
        return p
            .failed(reason::INVALID_PARAMETERS, "malformed Pairing Response")
            .await;
    };
    p.pres = rsp.as_slice().try_into().unwrap_or([0; 7]);
    p.theirs = theirs;
    p.run().await
}

/// Pairs as responder (peripheral), answering a Pairing Request.
async fn respond(
    host: &Host,
    conn: &Arc<ConnState>,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    req: &[u8],
) -> Result<Security> {
    let Some(theirs) = Features::parse(req) else {
        let _ = conn
            .send(
                host,
                cid::SMP,
                &[code::PAIRING_FAILED, reason::INVALID_PARAMETERS],
            )
            .await;
        return Err(Error::Pairing("malformed Pairing Request".into()));
    };
    let mut ours = local_features(host, conn.identity()).await;
    // Distribute only what both want.
    ours.init_keys &= theirs.init_keys;
    ours.resp_keys &= theirs.resp_keys;
    let pres = ours.pdu(code::PAIRING_RESPONSE);
    let p = Pairing {
        host,
        conn,
        rx,
        initiator: false,
        preq: req.try_into().unwrap_or([0; 7]),
        pres,
        ours,
        theirs,
    };
    p.send(&pres).await?;
    p.run().await
}

/// Encrypts with the bond's key, as central. `Ok(None)` when there is no bond.
async fn encrypt_with_bond(host: &Host, conn: &Arc<ConnState>) -> Result<Option<Security>> {
    let Some(bond) = host.inner.keys.bond(&conn.identity()) else {
        return Ok(None);
    };
    let Some(ltk) = bond.ltk else { return Ok(None) };
    let security = Security {
        encrypted: true,
        authenticated: bond.authenticated,
        secure_connections: bond.secure_connections,
        key_size: ltk.key_size,
        bonded: true,
    };
    let (tx, rx) = oneshot::channel();
    conn.waiters().encryption = Some(tx);
    host.inner
        .hci
        .exec_async(&LeEnableEncryption::new(
            ConnHandle::new(conn.handle),
            ltk.rand.to_le_bytes(),
            ltk.ediv,
            crypto::le(ltk.key),
        ))
        .await?;
    match tokio::time::timeout(SMP_TIMEOUT, rx).await {
        Ok(Ok(0)) => {
            conn.security.send_replace(security);
            Ok(Some(security))
        }
        Ok(Ok(s)) => Err(Error::Pairing(format!(
            "encryption with the stored key failed: {}",
            crate::error::status_name(s)
        ))),
        Ok(Err(_)) => Err(Error::Disconnected),
        Err(_) => Err(Error::Timeout("encryption")),
    }
}

/// Pairs now (central), or asks the central to (peripheral).
pub(crate) async fn pair(c: &Connection) -> Result<Security> {
    match c.state.role {
        Role::Central => {
            let (tx, rx) = oneshot::channel();
            let _one = c.state.security_op.lock().await;
            c.state
                .smp_cmd
                .send(Command::Pair(tx))
                .await
                .map_err(|_| Error::Disconnected)?;
            rx.await.map_err(|_| Error::Disconnected)?
        }
        Role::Peripheral => {
            let mut events = c.host.events();
            let auth = local_features(&c.host, c.identity()).await.auth;
            c.state
                .send(&c.host, cid::SMP, &[code::SECURITY_REQUEST, auth])
                .await?;
            let deadline = tokio::time::Instant::now() + SMP_TIMEOUT * 2;
            loop {
                match tokio::time::timeout_at(deadline, events.recv()).await {
                    Ok(Ok(HostEvent::Paired {
                        handle, security, ..
                    })) if handle == c.handle() => return Ok(security),
                    Ok(Ok(HostEvent::PairingFailed { handle, reason })) if handle == c.handle() => {
                        return Err(Error::Pairing(reason))
                    }
                    Ok(Ok(_)) | Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                        // The central may encrypt with our bond instead of pairing.
                        let s = c.security();
                        if s.encrypted && s.bonded {
                            return Ok(s);
                        }
                    }
                    Ok(Err(_)) => return Err(Error::Stopped),
                    Err(_) => return Err(Error::Timeout("the central to pair")),
                }
            }
        }
    }
}

/// Encrypts with a stored key, or pairs when there is none (or it fails).
pub(crate) async fn secure(c: &Connection) -> Result<Security> {
    if c.security().encrypted {
        return Ok(c.security());
    }
    if c.state.role == Role::Central {
        let one = c.state.security_op.lock().await;
        if c.security().encrypted {
            return Ok(c.security());
        }
        match encrypt_with_bond(&c.host, &c.state).await {
            Ok(Some(s)) => return Ok(s),
            Ok(None) => {}
            Err(e) => tracing::info!("{}: {e}; pairing again", c.identity()),
        }
        drop(one);
    }
    pair(c).await
}

/// The controller asks for the key to encrypt a connection on which we are
/// peripheral: a pairing's key, or a bond's.
pub(crate) fn on_ltk_request(host: &Host, handle: u16, rand: [u8; 8], ediv: u16) {
    let Some(conn) = host.state(handle) else {
        return;
    };
    let rand = u64::from_le_bytes(rand);
    let pairing = conn
        .pairing_key
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    let found: Option<(u128, Security)> = match pairing {
        Some(k) if ediv == 0 && rand == 0 => Some(k),
        _ => {
            let bond = if ediv == 0 && rand == 0 {
                host.inner
                    .keys
                    .bond(&conn.identity())
                    .filter(|b| b.secure_connections)
            } else {
                host.inner.keys.by_ediv_rand(ediv, rand)
            };
            bond.and_then(|b| {
                let k = if b.secure_connections {
                    b.ltk
                } else {
                    b.local_ltk
                }?;
                Some((
                    k.key,
                    Security {
                        encrypted: true,
                        authenticated: b.authenticated,
                        secure_connections: b.secure_connections,
                        key_size: k.key_size,
                        bonded: true,
                    },
                ))
            })
        }
    };
    let host = host.clone();
    tokio::spawn(async move {
        let h = ConnHandle::new(handle);
        let r = match found {
            Some((key, security)) => {
                if security.bonded {
                    // Applied when encryption comes on.
                    let (tx, rx) = oneshot::channel();
                    let had_waiter = {
                        let mut w = conn.waiters();
                        let had = w.encryption.is_some();
                        if !had {
                            w.encryption = Some(tx);
                        }
                        had
                    };
                    if !had_waiter {
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            if let Ok(Ok(0)) = tokio::time::timeout(SMP_TIMEOUT, rx).await {
                                conn.security.send_replace(security);
                            }
                        });
                    }
                }
                host.inner
                    .hci
                    .exec(&LeLongTermKeyRequestReply::new(h, crypto::le(key)))
                    .await
                    .map(|_| ())
            }
            None => host
                .inner
                .hci
                .exec(&LeLongTermKeyRequestNegativeReply::new(h))
                .await
                .map(|_| ()),
        };
        if let Err(e) = r {
            tracing::warn!("answering the LTK request on {handle:#05x}: {e}");
        }
    });
}

/// Pairing state shared with the event loop.
pub(crate) type PairingKey = Mutex<Option<(u128, Security)>>;

#[cfg(test)]
mod tests {
    use super::*;
    use IoCapability::*;

    #[test]
    fn association_models() {
        assert_eq!(
            method(DisplayYesNo, DisplayYesNo, true),
            Method::NumericComparison
        );
        assert_eq!(method(DisplayYesNo, DisplayYesNo, false), Method::JustWorks);
        assert_eq!(
            method(KeyboardOnly, DisplayOnly, false),
            Method::PasskeyInitiatorInputs
        );
        assert_eq!(
            method(DisplayOnly, KeyboardOnly, true),
            Method::PasskeyResponderInputs
        );
        assert_eq!(
            method(KeyboardOnly, KeyboardOnly, true),
            Method::PasskeyBothInput
        );
        assert_eq!(
            method(KeyboardDisplay, KeyboardDisplay, false),
            Method::PasskeyInitiatorInputs
        );
        assert_eq!(
            method(KeyboardDisplay, KeyboardDisplay, true),
            Method::NumericComparison
        );
        assert_eq!(
            method(NoInputNoOutput, KeyboardDisplay, true),
            Method::JustWorks
        );
    }

    #[test]
    fn features_and_masks() {
        assert!(Features::parse(&[1, 3, 0, 0x2d, 16, 3, 3]).is_some());
        assert!(Features::parse(&[1, 9, 0, 0x2d, 16, 3, 3]).is_none());
        assert!(Features::parse(&[1, 3, 0, 0x2d, 6, 3, 3]).is_none());
        assert_eq!(mask(u128::MAX, 7), 0x00ff_ffff_ffff_ffff);
        assert_eq!(mask(5, 16), 5);
    }
}
