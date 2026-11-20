//! Provisioning (Mesh Protocol 5.4), sans-IO: the provisioner and the
//! device as state machines that take and give Provisioning PDUs, carried
//! by any bearer (PB-ADV or PB-GATT). Algorithm
//! BTM_ECDH_P256_CMAC_AES128_AES_CCM, with No OOB, Static OOB, Output OOB
//! (numeric) and Input OOB (numeric) authentication.

use bluetooth_host::crypto::EcdhKey;

use crate::crypto::{self, Key};

/// Provisioning PDU types.
pub mod pdu {
    /// Provisioning Invite.
    pub const INVITE: u8 = 0x00;
    /// Provisioning Capabilities.
    pub const CAPABILITIES: u8 = 0x01;
    /// Provisioning Start.
    pub const START: u8 = 0x02;
    /// Provisioning Public Key.
    pub const PUBLIC_KEY: u8 = 0x03;
    /// Provisioning Input Complete.
    pub const INPUT_COMPLETE: u8 = 0x04;
    /// Provisioning Confirmation.
    pub const CONFIRMATION: u8 = 0x05;
    /// Provisioning Random.
    pub const RANDOM: u8 = 0x06;
    /// Provisioning Data.
    pub const DATA: u8 = 0x07;
    /// Provisioning Complete.
    pub const COMPLETE: u8 = 0x08;
    /// Provisioning Failed.
    pub const FAILED: u8 = 0x09;
}

/// Provisioning Failed error codes.
pub mod error {
    /// Invalid PDU.
    pub const INVALID_PDU: u8 = 0x01;
    /// Invalid Format.
    pub const INVALID_FORMAT: u8 = 0x02;
    /// Unexpected PDU.
    pub const UNEXPECTED_PDU: u8 = 0x03;
    /// Confirmation Failed.
    pub const CONFIRMATION_FAILED: u8 = 0x04;
    /// Out of Resources.
    pub const OUT_OF_RESOURCES: u8 = 0x05;
    /// Decryption Failed.
    pub const DECRYPTION_FAILED: u8 = 0x06;
    /// Unexpected Error.
    pub const UNEXPECTED_ERROR: u8 = 0x07;
    /// Cannot Assign Addresses.
    pub const CANNOT_ASSIGN_ADDRESSES: u8 = 0x08;
}

/// What a device can do (Provisioning Capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Elements.
    pub elements: u8,
    /// Supported algorithms (bit 0: P-256 with CMAC/AES-CCM).
    pub algorithms: u16,
    /// Public key out of band available.
    pub public_key_oob: bool,
    /// Static OOB available.
    pub static_oob: bool,
    /// Output OOB size (digits) and actions.
    pub output_oob: (u8, u16),
    /// Input OOB size and actions.
    pub input_oob: (u8, u16),
}

impl Capabilities {
    fn params(&self) -> [u8; 11] {
        let a = self.algorithms.to_be_bytes();
        let o = self.output_oob.1.to_be_bytes();
        let i = self.input_oob.1.to_be_bytes();
        [
            self.elements,
            a[0],
            a[1],
            u8::from(self.public_key_oob),
            u8::from(self.static_oob),
            self.output_oob.0,
            o[0],
            o[1],
            self.input_oob.0,
            i[0],
            i[1],
        ]
    }

    fn parse(p: &[u8]) -> Option<Self> {
        let p: &[u8; 11] = p.try_into().ok()?;
        if p[0] == 0 {
            return None;
        }
        Some(Capabilities {
            elements: p[0],
            algorithms: u16::from_be_bytes([p[1], p[2]]),
            public_key_oob: p[3] & 1 != 0,
            static_oob: p[4] & 1 != 0,
            output_oob: (p[5], u16::from_be_bytes([p[6], p[7]])),
            input_oob: (p[8], u16::from_be_bytes([p[9], p[10]])),
        })
    }
}

/// How the provisioner authenticates the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// No OOB (no authentication).
    None,
    /// A static OOB value (16 octets) both know.
    Static(Key),
    /// The device shows a number, the provisioner is told it (`size` digits).
    OutputNumeric(u8),
    /// The provisioner shows a number, the device is told it.
    InputNumeric(u8),
}

impl Auth {
    fn start(&self) -> [u8; 3] {
        // AuthMethod, AuthAction (Blink/Display numeric = 3 for output, Input numeric = 2), AuthSize
        match self {
            Auth::None => [0, 0, 0],
            Auth::Static(_) => [1, 0, 0],
            Auth::OutputNumeric(n) => [2, 3, *n],
            Auth::InputNumeric(n) => [3, 2, *n],
        }
    }
}

/// The network a device joins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisioningData {
    /// The network key.
    pub net_key: Key,
    /// Its index.
    pub key_index: u16,
    /// Key refresh (bit 0) and IV update (bit 1) flags.
    pub flags: u8,
    /// The current IV index.
    pub iv_index: u32,
    /// The device's primary element address.
    pub address: u16,
}

impl ProvisioningData {
    fn bytes(&self) -> [u8; 25] {
        let mut b = [0u8; 25];
        b[..16].copy_from_slice(&self.net_key);
        b[16..18].copy_from_slice(&self.key_index.to_be_bytes());
        b[18] = self.flags;
        b[19..23].copy_from_slice(&self.iv_index.to_be_bytes());
        b[23..25].copy_from_slice(&self.address.to_be_bytes());
        b
    }

    fn parse(b: &[u8]) -> Option<Self> {
        let b: &[u8; 25] = b.try_into().ok()?;
        let mut k = [0u8; 16];
        k.copy_from_slice(&b[..16]);
        let address = u16::from_be_bytes([b[23], b[24]]);
        if address == 0 || address & 0x8000 != 0 {
            return None;
        }
        Some(ProvisioningData {
            net_key: k,
            key_index: u16::from_be_bytes([b[16], b[17]]),
            flags: b[18],
            iv_index: u32::from_be_bytes([b[19], b[20], b[21], b[22]]),
            address,
        })
    }
}

/// What a step produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Send these PDUs, in order (none: just wait), then wait for the next.
    Send(Vec<Vec<u8>>),
    /// Show this number to the person (Input OOB on the provisioner; Output OOB on the device).
    Show(u32),
    /// Done on our side: the device key, and (on the device) what it joined.
    Done {
        /// The device key.
        device_key: Key,
        /// On the device: the network it was given.
        data: Option<ProvisioningData>,
    },
    /// The other side failed it, or we did (send the Failed PDU given).
    Failed {
        /// The error code.
        code: u8,
        /// A Provisioning Failed PDU to send, when the failure is ours.
        send: Option<Vec<u8>>,
    },
}

fn random() -> Key {
    let mut r = [0u8; 16];
    bluetooth_host::crypto::random_bytes(&mut r);
    r
}

fn auth_value(auth: &Auth, number: u32) -> Key {
    match auth {
        Auth::None => [0; 16],
        Auth::Static(k) => *k,
        // A numeric value goes in the last four octets, big-endian.
        Auth::OutputNumeric(_) | Auth::InputNumeric(_) => {
            let mut v = [0u8; 16];
            v[12..].copy_from_slice(&number.to_be_bytes());
            v
        }
    }
}

fn number(digits: u8) -> u32 {
    let mut b = [0u8; 4];
    bluetooth_host::crypto::random_bytes(&mut b);
    let max = 10u32.saturating_pow(u32::from(digits.clamp(1, 8)));
    u32::from_be_bytes(b) % max
}

/// The keys both sides derive once the public keys and randoms are known.
struct Session {
    secret: [u8; 32],
    confirmation_salt: Key,
    confirmation_key: Key,
}

impl Session {
    fn new(secret: [u8; 32], inputs: &[u8]) -> Self {
        let confirmation_salt = crypto::s1(inputs);
        let confirmation_key = crypto::k1(&secret, &confirmation_salt, b"prck");
        Session {
            secret,
            confirmation_salt,
            confirmation_key,
        }
    }

    fn confirmation(&self, random: &Key, auth: &Key) -> Key {
        let mut m = [0u8; 32];
        m[..16].copy_from_slice(random);
        m[16..].copy_from_slice(auth);
        crypto::cmac(&self.confirmation_key, &m)
    }

    /// (session key, session nonce, device key) from both randoms.
    fn keys(&self, random_provisioner: &Key, random_device: &Key) -> (Key, [u8; 13], Key) {
        let mut m = [0u8; 48];
        m[..16].copy_from_slice(&self.confirmation_salt);
        m[16..32].copy_from_slice(random_provisioner);
        m[32..].copy_from_slice(random_device);
        let salt = crypto::s1(&m);
        let session_key = crypto::k1(&self.secret, &salt, b"prsk");
        let n = crypto::k1(&self.secret, &salt, b"prsn");
        let mut nonce = [0u8; 13];
        nonce.copy_from_slice(&n[3..]);
        (session_key, nonce, crypto::k1(&self.secret, &salt, b"prdk"))
    }
}

fn public_key_pdu(k: &EcdhKey) -> Vec<u8> {
    let mut p = vec![pdu::PUBLIC_KEY];
    p.extend_from_slice(&k.x);
    p.extend_from_slice(&k.y);
    p
}

fn fail(code: u8) -> Step {
    Step::Failed {
        code,
        send: Some(vec![pdu::FAILED, code]),
    }
}

fn peer_failed(p: &[u8]) -> Option<Step> {
    (p.first() == Some(&pdu::FAILED)).then(|| Step::Failed {
        code: p.get(1).copied().unwrap_or(error::UNEXPECTED_ERROR),
        send: None,
    })
}

#[derive(PartialEq, Eq)]
enum PState {
    Capabilities,
    PublicKey,
    InputComplete,
    Confirmation,
    Random,
    Complete,
    Finished,
}

/// The provisioner's side of one provisioning.
pub struct Provisioner {
    state: PState,
    auth: Auth,
    data: ProvisioningData,
    key: EcdhKey,
    inputs: Vec<u8>,
    session: Option<Session>,
    random: Key,
    number: u32,
    device_confirmation: Key,
    capabilities: Option<Capabilities>,
    device_key: Option<Key>,
}

impl Provisioner {
    /// Starts: returns the provisioner and the Invite to send.
    pub fn start(attention_secs: u8, auth: Auth, data: ProvisioningData) -> (Self, Vec<u8>) {
        let invite = vec![pdu::INVITE, attention_secs];
        let p = Provisioner {
            state: PState::Capabilities,
            auth,
            data,
            key: EcdhKey::generate(),
            inputs: invite[1..].to_vec(),
            session: None,
            random: random(),
            number: 0,
            device_confirmation: [0; 16],
            capabilities: None,
            device_key: None,
        };
        (p, invite)
    }

    /// The device's capabilities, once known.
    pub fn capabilities(&self) -> Option<Capabilities> {
        self.capabilities
    }

    /// Output OOB: the number the device showed, typed by the person.
    pub fn enter_number(&mut self, n: u32) -> Option<Vec<u8>> {
        if self.state != PState::Confirmation || !matches!(self.auth, Auth::OutputNumeric(_)) {
            return None;
        }
        self.number = n;
        self.send_confirmation()
    }

    fn send_confirmation(&mut self) -> Option<Vec<u8>> {
        let s = self.session.as_ref()?;
        let c = s.confirmation(&self.random, &auth_value(&self.auth, self.number));
        let mut p = vec![pdu::CONFIRMATION];
        p.extend_from_slice(&c);
        self.state = PState::Confirmation;
        Some(p)
    }

    /// Takes the device's next PDU.
    pub fn receive(&mut self, p: &[u8]) -> Step {
        if let Some(f) = peer_failed(p) {
            return f;
        }
        let Some((&ty, body)) = p.split_first() else {
            return fail(error::INVALID_PDU);
        };
        match (&self.state, ty) {
            (PState::Capabilities, pdu::CAPABILITIES) => {
                let Some(c) = Capabilities::parse(body) else {
                    return fail(error::INVALID_FORMAT);
                };
                if c.algorithms & 1 == 0 {
                    return fail(error::INVALID_FORMAT);
                }
                self.capabilities = Some(c);
                let mut start = vec![pdu::START, 0x00, 0x00];
                start.extend_from_slice(&self.auth.start());
                self.inputs.extend_from_slice(body);
                self.inputs.extend_from_slice(&start[1..]);
                self.inputs.extend_from_slice(&self.key.x);
                self.inputs.extend_from_slice(&self.key.y);
                self.state = PState::PublicKey;
                // Start, then our public key.
                Step::Send(vec![start, public_key_pdu(&self.key)])
            }
            (PState::PublicKey, pdu::PUBLIC_KEY) => {
                let (Ok(x), Ok(y)) = (
                    <[u8; 32]>::try_from(&body[..body.len().min(32)]),
                    <[u8; 32]>::try_from(body.get(32..64).unwrap_or(&[])),
                ) else {
                    return fail(error::INVALID_FORMAT);
                };
                if body.len() != 64 {
                    return fail(error::INVALID_FORMAT);
                }
                let Some(secret) = self.key.dh_key(&x, &y) else {
                    return fail(error::UNEXPECTED_ERROR);
                };
                self.inputs.extend_from_slice(body);
                self.session = Some(Session::new(secret, &self.inputs));
                match self.auth {
                    Auth::InputNumeric(d) => {
                        self.number = number(d);
                        self.state = PState::InputComplete;
                        Step::Show(self.number)
                    }
                    Auth::OutputNumeric(_) => {
                        // Wait for the person to type what the device shows.
                        self.state = PState::Confirmation;
                        Step::Show(u32::MAX)
                    }
                    _ => match self.send_confirmation() {
                        Some(c) => Step::Send(vec![c]),
                        None => fail(error::UNEXPECTED_ERROR),
                    },
                }
            }
            (PState::InputComplete, pdu::INPUT_COMPLETE) => match self.send_confirmation() {
                Some(c) => Step::Send(vec![c]),
                None => fail(error::UNEXPECTED_ERROR),
            },
            (PState::Confirmation, pdu::CONFIRMATION) if body.len() == 16 => {
                self.device_confirmation.copy_from_slice(body);
                self.state = PState::Random;
                let mut r = vec![pdu::RANDOM];
                r.extend_from_slice(&self.random);
                Step::Send(vec![r])
            }
            (PState::Random, pdu::RANDOM) if body.len() == 16 => {
                let mut device_random = [0u8; 16];
                device_random.copy_from_slice(body);
                let Some(s) = &self.session else {
                    return fail(error::UNEXPECTED_ERROR);
                };
                if s.confirmation(&device_random, &auth_value(&self.auth, self.number))
                    != self.device_confirmation
                {
                    return fail(error::CONFIRMATION_FAILED);
                }
                let (session_key, nonce, device_key) = s.keys(&self.random, &device_random);
                let enc = crypto::ccm_encrypt(&session_key, &nonce, &[], &self.data.bytes(), 8);
                self.device_key = Some(device_key);
                self.state = PState::Complete;
                let mut d = vec![pdu::DATA];
                d.extend_from_slice(&enc);
                Step::Send(vec![d])
            }
            (PState::Complete, pdu::COMPLETE) => {
                self.state = PState::Finished;
                match self.device_key {
                    Some(k) => Step::Done {
                        device_key: k,
                        data: None,
                    },
                    None => fail(error::UNEXPECTED_ERROR),
                }
            }
            _ => fail(error::UNEXPECTED_PDU),
        }
    }
}

#[derive(PartialEq, Eq)]
enum DState {
    Invite,
    Start,
    PublicKey,
    Confirmation,
    Random,
    Data,
    Finished,
}

/// The device's side, so the gateway can be provisioned into a network (and
/// for testing the provisioner).
pub struct Device {
    state: DState,
    caps: Capabilities,
    static_oob: Option<Key>,
    key: EcdhKey,
    inputs: Vec<u8>,
    auth: Auth,
    number: u32,
    session: Option<Session>,
    random: Key,
    provisioner_confirmation: Key,
    provisioner_random: Key,
}

impl Device {
    /// A device with these capabilities (and its static OOB value, if it has one).
    pub fn new(caps: Capabilities, static_oob: Option<Key>) -> Self {
        Device {
            state: DState::Invite,
            caps,
            static_oob,
            key: EcdhKey::generate(),
            inputs: Vec::new(),
            auth: Auth::None,
            number: 0,
            session: None,
            random: random(),
            provisioner_confirmation: [0; 16],
            provisioner_random: [0; 16],
        }
    }

    /// Input OOB: the number the provisioner showed, typed into the device.
    pub fn enter_number(&mut self, n: u32) -> Option<Vec<u8>> {
        if self.state != DState::Confirmation || !matches!(self.auth, Auth::InputNumeric(_)) {
            return None;
        }
        self.number = n;
        Some(vec![pdu::INPUT_COMPLETE])
    }

    /// Takes the provisioner's next PDU.
    pub fn receive(&mut self, p: &[u8]) -> Step {
        if let Some(f) = peer_failed(p) {
            return f;
        }
        let Some((&ty, body)) = p.split_first() else {
            return fail(error::INVALID_PDU);
        };
        match (&self.state, ty) {
            (DState::Invite, pdu::INVITE) if body.len() == 1 => {
                self.inputs.extend_from_slice(body);
                let caps = self.caps.params();
                self.inputs.extend_from_slice(&caps);
                self.state = DState::Start;
                let mut c = vec![pdu::CAPABILITIES];
                c.extend_from_slice(&caps);
                Step::Send(vec![c])
            }
            (DState::Start, pdu::START) if body.len() == 5 => {
                if body[0] != 0 || body[1] != 0 {
                    return fail(error::INVALID_FORMAT);
                }
                self.auth = match (body[2], body[4]) {
                    (0, _) => Auth::None,
                    (1, _) => match self.static_oob {
                        Some(k) => Auth::Static(k),
                        None => return fail(error::INVALID_FORMAT),
                    },
                    (2, n) => Auth::OutputNumeric(n),
                    (3, n) => Auth::InputNumeric(n),
                    _ => return fail(error::INVALID_FORMAT),
                };
                self.inputs.extend_from_slice(body);
                self.state = DState::PublicKey;
                Step::Send(Vec::new())
            }
            (DState::PublicKey, pdu::PUBLIC_KEY) if body.len() == 64 => {
                let x: [u8; 32] = body[..32].try_into().unwrap_or([0; 32]);
                let y: [u8; 32] = body[32..].try_into().unwrap_or([0; 32]);
                if x == self.key.x {
                    return fail(error::UNEXPECTED_ERROR);
                }
                let Some(secret) = self.key.dh_key(&x, &y) else {
                    return fail(error::UNEXPECTED_ERROR);
                };
                self.inputs.extend_from_slice(body);
                self.inputs.extend_from_slice(&self.key.x);
                self.inputs.extend_from_slice(&self.key.y);
                self.session = Some(Session::new(secret, &self.inputs));
                self.state = DState::Confirmation;
                if let Auth::OutputNumeric(d) = self.auth {
                    self.number = number(d);
                    return Step::Show(self.number);
                }
                Step::Send(vec![public_key_pdu(&self.key)])
            }
            (DState::Confirmation, pdu::CONFIRMATION) if body.len() == 16 => {
                self.provisioner_confirmation.copy_from_slice(body);
                let Some(s) = &self.session else {
                    return fail(error::UNEXPECTED_ERROR);
                };
                let c = s.confirmation(&self.random, &auth_value(&self.auth, self.number));
                self.state = DState::Random;
                let mut p = vec![pdu::CONFIRMATION];
                p.extend_from_slice(&c);
                Step::Send(vec![p])
            }
            (DState::Random, pdu::RANDOM) if body.len() == 16 => {
                self.provisioner_random.copy_from_slice(body);
                let Some(s) = &self.session else {
                    return fail(error::UNEXPECTED_ERROR);
                };
                if s.confirmation(
                    &self.provisioner_random,
                    &auth_value(&self.auth, self.number),
                ) != self.provisioner_confirmation
                {
                    return fail(error::CONFIRMATION_FAILED);
                }
                self.state = DState::Data;
                let mut r = vec![pdu::RANDOM];
                r.extend_from_slice(&self.random);
                Step::Send(vec![r])
            }
            (DState::Data, pdu::DATA) if body.len() == 33 => {
                let Some(s) = &self.session else {
                    return fail(error::UNEXPECTED_ERROR);
                };
                let (session_key, nonce, device_key) =
                    s.keys(&self.provisioner_random, &self.random);
                let Some(plain) = crypto::ccm_decrypt(&session_key, &nonce, &[], body, 8) else {
                    return fail(error::DECRYPTION_FAILED);
                };
                let Some(data) = ProvisioningData::parse(&plain) else {
                    return fail(error::INVALID_FORMAT);
                };
                self.state = DState::Finished;
                Step::Done {
                    device_key,
                    data: Some(data),
                }
            }
            _ => fail(error::UNEXPECTED_PDU),
        }
    }

    /// The device's public key PDU (sent after the provisioner's when the
    /// device shows an Output OOB number).
    pub fn public_key(&self) -> Vec<u8> {
        public_key_pdu(&self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> Capabilities {
        Capabilities {
            elements: 2,
            algorithms: 1,
            public_key_oob: false,
            static_oob: true,
            output_oob: (4, 0x0008),
            input_oob: (4, 0x0008),
        }
    }

    fn data() -> ProvisioningData {
        ProvisioningData {
            net_key: [0x7d; 16],
            key_index: 0,
            flags: 0,
            iv_index: 0x1234_5678,
            address: 0x0b0c,
        }
    }

    /// Runs a provisioning between our two sides; the person types whatever
    /// is shown.
    fn run(
        auth: Auth,
        static_oob: Option<Key>,
        tamper: bool,
    ) -> Result<(Key, Key, ProvisioningData), u8> {
        let (mut p, invite) = Provisioner::start(5, auth, data());
        let mut d = Device::new(caps(), static_oob);
        let mut to_device = vec![invite];
        let mut shown_by_device = None;
        let mut shown_by_provisioner = None;
        let mut device_done = None;
        for _ in 0..20 {
            let Some(pdu) = to_device.pop() else { break };
            let mut pdu = pdu;
            if tamper && pdu.first() == Some(&pdu::RANDOM) {
                pdu[3] ^= 1;
            }
            let to_provisioner = match d.receive(&pdu) {
                Step::Send(v) if v.is_empty() => continue,
                Step::Send(v) => v,
                Step::Show(n) => {
                    shown_by_device = Some(n);
                    vec![d.public_key()]
                }
                Step::Done { device_key, data } => {
                    device_done = Some((device_key, data.unwrap()));
                    vec![vec![pdu::COMPLETE]]
                }
                Step::Failed { code, .. } => return Err(code),
            };
            for tp in to_provisioner {
                match p.receive(&tp) {
                    Step::Send(v) => to_device.extend(v.into_iter().rev()),
                    Step::Show(u32::MAX) => {
                        let c = p.enter_number(shown_by_device.unwrap()).unwrap();
                        to_device.push(c);
                    }
                    Step::Show(n) => {
                        shown_by_provisioner = Some(n);
                        let ic = d.enter_number(n).unwrap();
                        match p.receive(&ic) {
                            Step::Send(c) => to_device.extend(c),
                            other => panic!("{other:?}"),
                        }
                    }
                    Step::Done { device_key, .. } => {
                        let (dk, dd) = device_done.unwrap();
                        let _ = shown_by_provisioner;
                        return Ok((device_key, dk, dd));
                    }
                    Step::Failed { code, .. } => return Err(code),
                }
            }
        }
        Err(0xff)
    }

    #[test]
    fn every_auth_method_ends_with_the_same_device_key() {
        for (auth, so) in [
            (Auth::None, None),
            (Auth::Static([0x5a; 16]), Some([0x5a; 16])),
            (Auth::OutputNumeric(4), None),
            (Auth::InputNumeric(4), None),
        ] {
            let (pk, dk, d) = run(auth, so, false).unwrap_or_else(|e| panic!("{auth:?}: {e}"));
            assert_eq!(pk, dk, "{auth:?}");
            assert_eq!(d, data());
        }
    }

    #[test]
    fn a_wrong_static_value_or_tampered_random_fails_confirmation() {
        assert_eq!(
            run(Auth::Static([1; 16]), Some([2; 16]), false),
            Err(error::CONFIRMATION_FAILED)
        );
        assert_eq!(run(Auth::None, None, true), Err(error::CONFIRMATION_FAILED));
    }

    #[test]
    fn malformed_pdus_fail_cleanly() {
        let (mut p, _) = Provisioner::start(0, Auth::None, data());
        assert!(matches!(
            p.receive(&[pdu::CAPABILITIES, 1, 2]),
            Step::Failed {
                code: error::INVALID_FORMAT,
                ..
            }
        ));
        assert!(matches!(p.receive(&[]), Step::Failed { .. }));
        let mut d = Device::new(caps(), None);
        assert!(matches!(
            d.receive(&[pdu::DATA; 34]),
            Step::Failed {
                code: error::UNEXPECTED_PDU,
                ..
            }
        ));
    }
}
