//! Bluetooth Mesh in the bridge: the bridge as a mesh's provisioner, on the
//! advertising bearer of the controller it already scans with.
//!
//! The network (keys, the nodes it provisioned) lives in `<data>/mesh`, and is
//! created on the first start with `[mesh] enabled = true`. Requests on
//! `<base>/bridge/request/mesh/<op>`, answered on `<base>/bridge/response/mesh/<op>`:
//!
//! | op | body | answer |
//! |---|---|---|
//! | `network` | | the bridge's address, IV index, and the nodes |
//! | `unprovisioned` | | the devices whose beacons were heard, newest first |
//! | `provision` | `uuid` (hex), optional `static_oob` (hex) | the node: address, elements |
//! | `configure` | `address` | its Composition Data, after the AppKey and bindings |
//! | `onoff` | `address`, `on` | the Generic OnOff state it reports |
//!
//! Events on `<base>/mesh/event`: `unprovisioned` (a new beacon) and
//! `message` (an access message to the bridge).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bluetooth_host::Host;
use bluetooth_mesh_stack::access::{Composition, ModelId};
use bluetooth_mesh_stack::provisioning::Auth;
use bluetooth_mesh_stack::runtime::{ad, run_host_bearer, HostBearer, Mesh, MeshEvent};
use serde_json::{json, Value};

use crate::mqtt::Mqtt;

/// The AD types Mesh is carried in, reported by the scanner every time.
pub const AD_TYPES: [u8; 3] = [ad::PB_ADV, ad::MESSAGE, ad::BEACON];

/// Unprovisioned devices heard: UUID -> (OOB information, when, seconds).
type Heard = Arc<Mutex<HashMap<[u8; 16], (u16, u64)>>>;

/// The bridge's mesh.
#[derive(Clone)]
pub struct BridgeMesh {
    mesh: Mesh,
    heard: Heard,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl BridgeMesh {
    /// Opens (or creates) the network in `dir` and starts hearing it.
    pub fn start(
        host: &Host,
        dir: std::path::PathBuf,
        mqtt: Mqtt,
        base: String,
    ) -> Result<BridgeMesh, String> {
        let mesh = Mesh::open(HostBearer::new(host.clone()), Some(dir), [0; 16])
            .map_err(|e| format!("the mesh store: {e}"))?;
        if mesh.store().net_keys.is_empty() {
            mesh.create_network();
            tracing::info!("mesh: created a network, the bridge at 0x0001");
        }
        tokio::spawn(run_host_bearer(host.clone(), mesh.clone()));
        let heard: Heard = Arc::default();
        let (h, mut events) = (heard.clone(), mesh.events());
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(MeshEvent::Unprovisioned { uuid, oob_info }) => {
                        let new = lock(&h).insert(uuid, (oob_info, now())).is_none();
                        if new {
                            mqtt.publish_json(
                                format!("{base}/mesh/event"),
                                &json!({"type": "unprovisioned", "uuid": hex::encode(uuid), "oob_info": oob_info}),
                                false,
                            );
                        }
                    }
                    Ok(MeshEvent::Message {
                        src,
                        dst,
                        opcode,
                        params,
                    }) => mqtt.publish_json(
                        format!("{base}/mesh/event"),
                        &json!({"type": "message", "src": src, "dst": dst,
                                "opcode": format!("{opcode:?}"), "params": hex::encode(params)}),
                        false,
                    ),
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => return,
                }
            }
        });
        Ok(BridgeMesh { mesh, heard })
    }

    /// One `mesh/<op>` request.
    pub async fn request(&self, op: &str, body: &Value) -> Result<Value, String> {
        let address = || -> Result<u16, String> {
            body.get("address")
                .and_then(Value::as_u64)
                .and_then(|a| u16::try_from(a).ok())
                .filter(|a| *a != 0 && a & 0x8000 == 0)
                .ok_or_else(|| "`address` must be a node's unicast address".to_string())
        };
        let key16 = |name: &str| -> Result<Option<[u8; 16]>, String> {
            match body.get(name).and_then(Value::as_str) {
                None => Ok(None),
                Some(s) => hex::decode(s)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .map(Some)
                    .ok_or_else(|| format!("`{name}` must be 16 octets in hex")),
            }
        };
        match op {
            "network" => {
                let s = self.mesh.store();
                Ok(json!({
                    "address": s.address,
                    "iv_index": s.iv_index,
                    "nodes": s.nodes.iter().map(|n| json!({
                        "uuid": hex::encode(n.uuid), "address": n.address, "elements": n.elements,
                    })).collect::<Vec<_>>(),
                }))
            }
            "unprovisioned" => {
                let mut v: Vec<_> = lock(&self.heard)
                    .iter()
                    .map(|(u, (oob, at))| {
                        (
                            *at,
                            json!({"uuid": hex::encode(u), "oob_info": oob, "heard": at}),
                        )
                    })
                    .collect();
                v.sort_by_key(|x| std::cmp::Reverse(x.0));
                Ok(json!(v.into_iter().map(|(_, j)| j).collect::<Vec<_>>()))
            }
            "provision" => {
                let uuid = key16("uuid")?.ok_or("`uuid` is required")?;
                let auth = match key16("static_oob")? {
                    Some(k) => Auth::Static(k),
                    None => Auth::None,
                };
                let n =
                    tokio::time::timeout(Duration::from_secs(120), self.mesh.provision(uuid, auth))
                        .await
                        .map_err(|_| "provisioning timed out".to_string())?
                        .map_err(|e| e.to_string())?;
                lock(&self.heard).remove(&uuid);
                Ok(
                    json!({"uuid": hex::encode(n.uuid), "address": n.address, "elements": n.elements}),
                )
            }
            "configure" => {
                let a = address()?;
                let node = self
                    .mesh
                    .store()
                    .nodes
                    .into_iter()
                    .find(|n| n.address == a)
                    .ok_or("no node with that address was provisioned here")?;
                let c = tokio::time::timeout(Duration::from_secs(60), self.mesh.configure(&node))
                    .await
                    .map_err(|_| "configuration timed out".to_string())?
                    .map_err(|e| e.to_string())?;
                Ok(composition(&c))
            }
            "onoff" => {
                let a = address()?;
                let on = body
                    .get("on")
                    .and_then(Value::as_bool)
                    .ok_or("`on` must be true or false")?;
                let tid = (now() & 0xff) as u8;
                let present =
                    tokio::time::timeout(Duration::from_secs(30), self.mesh.onoff_set(a, on, tid))
                        .await
                        .map_err(|_| "no answer".to_string())?
                        .map_err(|e| e.to_string())?;
                Ok(json!({"on": present}))
            }
            _ => Err(format!("unknown request mesh/{op}")),
        }
    }
}

fn composition(c: &Composition) -> Value {
    let model = |m: &ModelId| match m {
        ModelId::Sig(id) => json!({
            "id": format!("{id:04x}"),
            "name": bluetooth_numbers::mesh_model(*id),
        }),
        ModelId::Vendor(company, id) => json!({
            "company": company,
            "company_name": bluetooth_numbers::company(*company),
            "id": format!("{id:04x}"),
        }),
    };
    json!({
        "company": c.cid,
        "company_name": bluetooth_numbers::company(c.cid),
        "product": c.pid,
        "version": c.vid,
        "features": {
            "relay": c.features & 1 != 0,
            "proxy": c.features & 2 != 0,
            "friend": c.features & 4 != 0,
            "low_power": c.features & 8 != 0,
        },
        "elements": c.elements.iter().map(|e| json!({
            "location": e.location,
            "models": e.models.iter().map(model).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

/// Whether an advertisement is only Mesh (not worth publishing as a report).
pub fn only_mesh(data: &[u8]) -> bool {
    let mut any = false;
    for s in bluetooth_host::adv::AdStructures::new(data).flatten() {
        if !AD_TYPES.contains(&s.ad_type) {
            return false;
        }
        any = true;
    }
    any
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_only_advertisements() {
        assert!(only_mesh(&[4, 0x29, 1, 2, 3]));
        assert!(only_mesh(&[3, 0x2a, 1, 2, 3, 0x2b, 9, 9]));
        assert!(!only_mesh(&[2, 1, 6, 4, 0x29, 1, 2, 3]));
        assert!(!only_mesh(&[]));
    }
}
