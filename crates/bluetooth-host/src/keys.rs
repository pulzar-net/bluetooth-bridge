//! Bonds (the keys pairing leaves behind), our own identity, and resolving
//! private addresses to the identities they hide.
//!
//! Kept as two JSON files in the data directory, written whole to a
//! temporary file and renamed, mode 0600: `identity.json` (our IRK and
//! static random address) and `bonds.json`.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::crypto;
use crate::error::Result;

/// A long-term key and how to find it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LongTermKey {
    /// The key.
    #[serde(with = "hex_u128")]
    pub key: u128,
    /// Encrypted Diversifier (0 for Secure Connections).
    pub ediv: u16,
    /// Random number (0 for Secure Connections).
    pub rand: u64,
    /// Key size, octets.
    pub key_size: u8,
}

/// What we keep about a bonded (or otherwise known) device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bond {
    /// The device's identity address.
    pub identity: Address,
    /// The key to encrypt with: the Secure Connections LTK, or under legacy
    /// pairing the one the peer distributed (used when we are central).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ltk: Option<LongTermKey>,
    /// Under legacy pairing, the LTK we distributed (used when we are peripheral).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_ltk: Option<LongTermKey>,
    /// The device's Identity Resolving Key.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "hex_u128_opt"
    )]
    pub irk: Option<u128>,
    /// The device's Connection Signature Resolving Key.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "hex_u128_opt"
    )]
    pub csrk: Option<u128>,
    /// The pairing had MITM protection.
    #[serde(default)]
    pub authenticated: bool,
    /// The pairing used Secure Connections.
    #[serde(default)]
    pub secure_connections: bool,
    /// Its GATT client configuration on our server: (value handle, bits).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cccd: Vec<(u16, u16)>,
    /// A label, for IRKs entered by hand (tags whose IRK is known without pairing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Other (non-resolvable) addresses the device paired from: some
    /// devices distribute a public identity but connect from a static random
    /// address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<Address>,
}

impl Bond {
    /// A bond with nothing in it yet.
    pub fn new(identity: Address) -> Self {
        Bond {
            identity,
            ltk: None,
            local_ltk: None,
            irk: None,
            csrk: None,
            authenticated: false,
            secure_connections: false,
            cccd: Vec::new(),
            label: None,
            aliases: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Identity {
    #[serde(with = "hex_u128")]
    irk: u128,
    address: Address,
}

/// Bonds and our identity.
pub struct Keys {
    dir: Option<PathBuf>,
    identity: Identity,
    bonds: Mutex<Vec<Bond>>,
    cache: Mutex<HashMap<[u8; 6], Option<Address>>>,
}

/// Resolved (and unresolvable) private addresses remembered, so a busy site
/// does not run AES for every advertisement.
const CACHE_LIMIT: usize = 4096;

impl Keys {
    /// Opens (or creates) the key files in `dir`; `None` keeps everything in memory.
    pub fn open(dir: Option<&Path>) -> Result<Keys> {
        let identity = match dir.map(|d| d.join("identity.json")) {
            Some(p) if p.exists() => serde_json::from_slice(&fs::read(&p)?)
                .map_err(|e| crate::Error::Protocol(format!("{}: {e}", p.display())))?,
            _ => {
                let id = Identity {
                    irk: crypto::random_u128(),
                    address: Address::new_static_random(),
                };
                if let Some(d) = dir {
                    fs::create_dir_all(d)?;
                    write_private(
                        &d.join("identity.json"),
                        &serde_json::to_vec_pretty(&id).unwrap_or_default(),
                    )?;
                }
                id
            }
        };
        let bonds = match dir.map(|d| d.join("bonds.json")) {
            Some(p) if p.exists() => serde_json::from_slice(&fs::read(&p)?)
                .map_err(|e| crate::Error::Protocol(format!("{}: {e}", p.display())))?,
            _ => Vec::new(),
        };
        Ok(Keys {
            dir: dir.map(Path::to_path_buf),
            identity,
            bonds: Mutex::new(bonds),
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Our static random address (used when the controller has no public one).
    pub fn local_static_address(&self) -> Address {
        self.identity.address
    }

    /// Our Identity Resolving Key, distributed when pairing.
    pub fn local_irk(&self) -> u128 {
        self.identity.irk
    }

    /// Every bond.
    pub fn bonds(&self) -> Vec<Bond> {
        self.bonds.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The bond with a device, by identity address.
    pub fn bond(&self, identity: &Address) -> Option<Bond> {
        self.bonds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|b| b.identity == *identity)
            .cloned()
    }

    /// Stores (or replaces) a bond.
    pub fn store(&self, bond: Bond) -> Result<()> {
        let mut b = self.bonds.lock().unwrap_or_else(|e| e.into_inner());
        b.retain(|x| x.identity != bond.identity);
        b.push(bond);
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.save(&b)
    }

    /// Updates a bond in place, if there is one.
    pub fn update(&self, identity: &Address, f: impl FnOnce(&mut Bond)) -> Result<bool> {
        let mut b = self.bonds.lock().unwrap_or_else(|e| e.into_inner());
        let Some(x) = b.iter_mut().find(|x| x.identity == *identity) else {
            return Ok(false);
        };
        f(x);
        self.save(&b)?;
        Ok(true)
    }

    /// Forgets a device. Returns whether there was a bond.
    pub fn remove(&self, identity: &Address) -> Result<bool> {
        let mut b = self.bonds.lock().unwrap_or_else(|e| e.into_inner());
        let before = b.len();
        b.retain(|x| x.identity != *identity);
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let removed = b.len() != before;
        self.save(&b)?;
        Ok(removed)
    }

    /// Records an IRK known without pairing (some tags print theirs), so the
    /// device's private addresses resolve to `identity`.
    pub fn add_irk(&self, identity: Address, irk: u128, label: Option<String>) -> Result<()> {
        let mut bond = self.bond(&identity).unwrap_or_else(|| Bond::new(identity));
        bond.irk = Some(irk);
        if label.is_some() {
            bond.label = label;
        }
        self.store(bond)
    }

    /// The identity a device uses this address for: resolved from an IRK
    /// for a private address, or a bond's identity or alias.
    pub fn identity_of(&self, addr: &Address) -> Option<Address> {
        if addr.is_resolvable() {
            return self.resolve(addr);
        }
        self.bonds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|b| b.identity == *addr || b.aliases.contains(addr))
            .map(|b| b.identity)
    }

    /// The identity behind a resolvable private address, from the stored IRKs.
    pub fn resolve(&self, addr: &Address) -> Option<Address> {
        if !addr.is_resolvable() {
            return None;
        }
        if let Some(hit) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&addr.bytes)
        {
            return *hit;
        }
        let found = self
            .bonds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|b| b.irk.is_some_and(|irk| crypto::resolves(irk, &addr.bytes)))
            .map(|b| b.identity);
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if c.len() >= CACHE_LIMIT {
            c.clear();
        }
        c.insert(addr.bytes, found);
        found
    }

    /// The bond whose local (legacy) LTK has this EDIV and Rand.
    pub(crate) fn by_ediv_rand(&self, ediv: u16, rand: u64) -> Option<Bond> {
        self.bonds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|b| {
                b.local_ltk
                    .is_some_and(|k| k.ediv == ediv && k.rand == rand)
            })
            .cloned()
    }

    fn save(&self, bonds: &[Bond]) -> Result<()> {
        if let Some(d) = &self.dir {
            write_private(
                &d.join("bonds.json"),
                &serde_json::to_vec_pretty(bonds).unwrap_or_default(),
            )?;
        }
        Ok(())
    }
}

/// Writes a file readable only by its owner, atomically.
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut o = fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)
}

mod hex_u128 {
    pub fn serialize<S: serde::Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{v:032x}"))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        u128::from_str_radix(s.trim(), 16).map_err(serde::de::Error::custom)
    }
}

mod hex_u128_opt {
    pub fn serialize<S: serde::Serializer>(v: &Option<u128>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_str(&format!("{v:032x}")),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u128>, D::Error> {
        let s = <Option<String> as serde::Deserialize>::deserialize(d)?;
        s.map(|s| u128::from_str_radix(s.trim(), 16).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_and_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let k = Keys::open(Some(dir.path())).unwrap();
        let me = k.local_static_address();
        let irk = 0x1234_5678_9abc_def0_1122_3344_5566_7788u128;
        let id: Address = "11:22:33:44:55:66".parse().unwrap();
        k.add_irk(id, irk, Some("tag".into())).unwrap();
        let rpa = Address::random(crypto::new_rpa(irk));
        assert_eq!(k.resolve(&rpa), Some(id));
        assert_eq!(k.resolve(&Address::random(crypto::new_rpa(irk ^ 1))), None);

        let k2 = Keys::open(Some(dir.path())).unwrap();
        assert_eq!(k2.local_static_address(), me);
        assert_eq!(k2.bond(&id).unwrap().irk, Some(irk));
        assert!(k2.remove(&id).unwrap());
        assert!(Keys::open(Some(dir.path())).unwrap().bonds().is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("bonds.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
