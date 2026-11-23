//! The bridge: the host's events out to MQTT, requests from MQTT in.
//!
//! Every topic's payload is a type in [`crate::api`], which is the contract
//! and from which the docs' MQTT reference is generated.
//!
//! Addresses in topics are twelve upper-case hex digits, most significant
//! first (`BC5729000001`).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bluetooth_adv::beacon::{self, Beacon};
use bluetooth_host::{
    Address, ConnEvent, Connection, FixedAgent, Host, HostConfig, HostEvent, Report, ScanConfig,
    TransportSpec,
};
use serde::de::DeserializeOwned;
use serde_json::Value as Json;

use crate::api::*;
use crate::config::Config;
use crate::ha;
use crate::mqtt::{self, Incoming, Mqtt};

/// The topic form of an address.
pub fn topic_id(a: &Address) -> String {
    a.to_string().replace(':', "")
}

struct Bridge {
    config: Config,
    host: Host,
    mqtt: Mqtt,
    base: String,
    beacon_ctx: beacon::Context,
    allow: Vec<Vec<u8>>,
    discovered: HashSet<(String, String)>,
    mesh: Option<crate::mesh::BridgeMesh>,
}

/// Runs the bridge until a signal or a fatal error.
pub async fn run(config: Config) -> Result<(), String> {
    let base = config.mqtt.base_topic.clone();
    let (mqtt, mut incoming) = mqtt::connect(&config.mqtt)?;
    let spec: TransportSpec = config.adapter.transport.parse()?;
    let host = open_host(&spec, &config).await;
    let mut b = Bridge::new(config, host, mqtt, base)?;
    b.setup().await;
    let mut events = b.host.events();
    loop {
        tokio::select! {
            e = events.recv() => match e {
                Ok(HostEvent::Stopped(reason)) => {
                    b.mqtt.publish_reliable(mqtt::state_topic(&b.base), BridgeState::payload(Availability::Offline), true).await;
                    return Err(format!("the Bluetooth host stopped: {reason}"));
                }
                Ok(e) => b.on_host_event(e).await,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("dropped {n} host events (MQTT too slow?)");
                }
                Err(_) => return Err("host event channel closed".into()),
            },
            m = incoming.recv() => match m {
                Some(Incoming::Connected) => b.on_mqtt_connected().await,
                Some(Incoming::Message { topic, payload }) => b.on_message(&topic, &payload).await,
                None => return Err("MQTT session ended".into()),
            },
            _ = shutdown() => {
                tracing::info!("stopping");
                let _ = b.host.stop_scan().await;
                b.mqtt.publish_reliable(mqtt::state_topic(&b.base), BridgeState::payload(Availability::Offline), true).await;
                b.mqtt.disconnect().await;
                return Ok(());
            }
        }
    }
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return std::future::pending().await,
            };
        tokio::select! {
            _ = term.recv() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Opens the controller, retrying while it is absent (unplugged, or still
/// loading firmware).
async fn open_host(spec: &TransportSpec, config: &Config) -> Host {
    let mut delay = Duration::from_secs(1);
    loop {
        match Host::open(spec, host_config(config)).await {
            Ok(h) => return h,
            Err(e) => {
                tracing::warn!("opening {spec}: {e}; retrying in {}s", delay.as_secs());
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(30));
            }
        }
    }
}

fn host_config(c: &Config) -> HostConfig {
    HostConfig {
        data_dir: Some(c.data.dir.clone()),
        device_name: c.adapter.name.clone(),
        appearance: c.adapter.appearance,
        io_capability: c.adapter.io_capability,
        agent: Arc::new(FixedAgent {
            passkey: c.adapter.passkey,
            confirm: true,
            oob: None,
        }),
        bonding: c.adapter.bonding,
        mitm: c.adapter.mitm,
        secure_connections_only: c.adapter.secure_connections_only,
        use_public_address: !c.adapter.random_address,
        ..HostConfig::default()
    }
}

fn parse_prefix(p: &str) -> Vec<u8> {
    let hex: String = p.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    hex::decode(if hex.len() % 2 == 1 {
        &hex[..hex.len() - 1]
    } else {
        &hex
    })
    .unwrap_or_default()
}

impl Bridge {
    fn new(config: Config, host: Host, mqtt: Mqtt, base: String) -> Result<Bridge, String> {
        let mut ctx = beacon::Context::default();
        for k in &config.bthome_keys {
            let a: Address = k.address.parse().map_err(|e| format!("{e}"))?;
            let key: [u8; 16] = hex::decode(&k.key)
                .ok()
                .and_then(|v| v.try_into().ok())
                .ok_or("bthome key")?;
            ctx.bthome_keys.insert(a.bytes, key);
        }
        for p in &config.kkm_passwords {
            let a: Address = p.address.parse().map_err(|e| format!("{e}"))?;
            ctx.kkm_passwords.insert(a.bytes, p.password.clone());
        }
        let allow = config.scan.allow.iter().map(|p| parse_prefix(p)).collect();
        Ok(Bridge {
            config,
            host,
            mqtt,
            base,
            beacon_ctx: ctx,
            allow,
            discovered: HashSet::new(),
            mesh: None,
        })
    }

    /// A scan configuration with Mesh's AD types always reported, when the
    /// mesh is on: its retransmissions are identical, and must be heard.
    fn scan_config(&self, mut c: ScanConfig) -> ScanConfig {
        if self.config.mesh.enabled {
            for t in crate::mesh::AD_TYPES {
                if !c.always_report.contains(&t) {
                    c.always_report.push(t);
                }
            }
        }
        c
    }

    async fn setup(&mut self) {
        if self.config.mesh.enabled {
            match crate::mesh::BridgeMesh::start(
                &self.host,
                self.config.data.dir.join("mesh"),
                self.mqtt.clone(),
                self.base.clone(),
            ) {
                Ok(m) => self.mesh = Some(m),
                Err(e) => tracing::error!("mesh: {e}"),
            }
        }
        for i in &self.config.irks {
            let (Ok(a), Ok(irk)) = (
                i.address.parse::<Address>(),
                u128::from_str_radix(&i.irk, 16),
            ) else {
                continue;
            };
            if let Err(e) = self.host.keys().add_irk(a, irk, i.label.clone()) {
                tracing::warn!("storing the IRK for {a}: {e}");
            }
        }
        let server = self.host.gatt_server();
        for s in self.config.gatt_services.clone() {
            if let Err(e) = server.add(&s).await {
                tracing::error!("GATT service {}: {e}", s.uuid);
            }
        }
        for a in self.config.advertising.clone() {
            let data = hex::decode(&a.data).unwrap_or_default();
            let sr = hex::decode(&a.scan_response).unwrap_or_default();
            if let Err(e) = self.host.advertise(&a.params, &data, &sr).await {
                tracing::error!("advertising set: {e}");
            }
        }
        if self.config.scan.enabled {
            if let Err(e) = self
                .host
                .start_scan(self.scan_config(self.config.scan.config.clone()))
                .await
            {
                tracing::error!("starting the scan: {e}");
            }
        }
    }

    async fn on_mqtt_connected(&mut self) {
        let base = self.base.clone();
        self.mqtt
            .subscribe(&format!("{base}/bridge/request/#"))
            .await;
        if self.config.homeassistant.enabled {
            self.mqtt
                .subscribe(&self.config.homeassistant.status_topic.clone())
                .await;
        }
        self.mqtt
            .publish_reliable(
                mqtt::state_topic(&base),
                BridgeState::payload(Availability::Online),
                true,
            )
            .await;
        self.mqtt
            .publish_reliable_json(format!("{base}/bridge/info"), &self.info(), true)
            .await;
        self.discovered.clear();
        if self.config.homeassistant.enabled {
            let (t, c) = ha::bridge_device(
                &self.config.homeassistant.discovery_prefix,
                &base,
                env!("CARGO_PKG_VERSION"),
            );
            self.mqtt.publish_reliable_json(t, &c, true).await;
        }
    }

    fn info(&self) -> BridgeInfo {
        let c = self.host.capabilities();
        BridgeInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            address: self.host.address(),
            controller: c.clone(),
            manufacturer_name: c.manufacturer_name().map(str::to_string),
            core_version: c.version_name().map(str::to_string),
            le_features: names(c.le_feature_names()),
            transport: self.config.adapter.transport.clone(),
        }
    }

    fn allowed(&self, a: &Address) -> bool {
        if self.allow.is_empty() {
            return true;
        }
        let msb: Vec<u8> = a.bytes.iter().rev().copied().collect();
        self.allow
            .iter()
            .any(|p| !p.is_empty() && msb.starts_with(p))
    }

    async fn on_host_event(&mut self, e: HostEvent) {
        let base = self.base.clone();
        let event = match e {
            HostEvent::Advertisement(r) => return self.on_report(&r).await,
            HostEvent::Connected(c) => {
                let event = BridgeEvent::Connected {
                    handle: c.handle(),
                    address: c.peer(),
                    identity: c.identity(),
                    role: c.role(),
                };
                self.watch_connection(c);
                event
            }
            HostEvent::Disconnected {
                handle,
                peer,
                reason,
            } => BridgeEvent::Disconnected {
                handle,
                address: peer,
                reason,
                reason_name: bluetooth_host::error::status_name(reason).into(),
            },
            HostEvent::Paired {
                handle,
                identity,
                bonded,
                security,
            } => BridgeEvent::Paired {
                handle,
                identity,
                bonded,
                security,
                level: security.level(),
            },
            HostEvent::PairingFailed { handle, reason } => {
                BridgeEvent::PairingFailed { handle, reason }
            }
            HostEvent::GattWrite {
                handle,
                attribute,
                value,
            } => BridgeEvent::GattWrite {
                handle,
                attribute,
                value: hex::encode(value),
            },
            HostEvent::GattSubscription {
                handle,
                attribute,
                notify,
                indicate,
            } => BridgeEvent::GattSubscription {
                handle,
                attribute,
                notify,
                indicate,
            },
            HostEvent::PeriodicReport(r) => BridgeEvent::PeriodicReport {
                advertisement: Box::new(bluetooth_adv::Advertisement::parse(&r.data)),
                report: (*r).clone(),
            },
            HostEvent::PeriodicSyncLost { sync } => BridgeEvent::PeriodicSyncLost { sync },
            HostEvent::AdvertisingStopped { set, connection } => {
                BridgeEvent::AdvertisingStopped { set, connection }
            }
            HostEvent::ScanRequest { set, scanner } => BridgeEvent::ScanRequest { set, scanner },
            other => return tracing::debug!("{base}: {other:?}"),
        };
        self.mqtt
            .publish_json(format!("{}/bridge/event", self.base), &event, false);
    }

    /// Forwards a connection's notifications as events.
    fn watch_connection(&self, c: Connection) {
        let mqtt = self.mqtt.clone();
        let topic = format!("{}/bridge/event", self.base);
        let mut rx = c.events();
        tokio::spawn(async move {
            loop {
                let event = match rx.recv().await {
                    Ok(ConnEvent::Notification {
                        handle,
                        value,
                        indication,
                    }) => BridgeEvent::Notification {
                        handle: c.handle(),
                        attribute: handle,
                        value: hex::encode(value),
                        indication,
                    },
                    Ok(ConnEvent::Disconnected(_))
                    | Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    Ok(other) => BridgeEvent::ConnectionChanged {
                        handle: c.handle(),
                        change: format!("{other:?}"),
                    },
                    Err(_) => continue,
                };
                mqtt.publish_json(topic.clone(), &event, false);
            }
        });
    }

    async fn on_report(&mut self, r: &Report) {
        if self.mesh.is_some() && crate::mesh::only_mesh(&r.data) {
            // The mesh's own traffic, heard through its bearer; not a device.
            return;
        }
        let device = r.device();
        if r.rssi < self.config.scan.min_rssi
            || !(self.allowed(&r.address) || self.allowed(&device))
        {
            return;
        }
        let adv = r.advertisement();
        let mut ctx = self.beacon_ctx.clone();
        ctx.address = Some(r.address.bytes);
        // Keys are stored by identity; use them for a private address too.
        if let Some(id) = r.identity {
            if let Some(k) = self.beacon_ctx.bthome_keys.get(&id.bytes) {
                ctx.bthome_keys.insert(r.address.bytes, *k);
            }
        }
        let beacons = beacon::decode(&adv, &ctx);
        let id = topic_id(&device);
        let readings: Vec<_> = beacons.iter().flat_map(Beacon::readings).collect();
        let name = adv.local_name.as_ref().map(|n| n.name.clone());
        let model = beacons
            .first()
            .map(|b| b.format())
            .unwrap_or("Bluetooth LE")
            .to_string();
        let manufacturer = adv.manufacturer_data.first().and_then(|m| m.company);
        if self.config.scan.publish_reports {
            let report = ScanReport {
                report: r.clone(),
                advertisement: adv,
                name: name.clone(),
                beacons,
            };
            self.mqtt
                .publish_json(format!("{}/scan/{id}", self.base), &report, false);
        }
        if readings.is_empty() {
            return;
        }
        let state = DeviceState {
            readings: readings
                .iter()
                .map(|x| (x.key.clone(), serde_json::json!(x.value)))
                .collect(),
            rssi: r.rssi,
            last_seen: r
                .time
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        };
        self.mqtt
            .publish_json(format!("{}/device/{id}", self.base), &state, false);
        if self.config.homeassistant.enabled {
            let name = name.unwrap_or_else(|| device.to_string());
            let mut keys: Vec<(String, &'static str)> =
                readings.iter().map(|x| (x.key.clone(), x.unit)).collect();
            keys.push(("rssi".into(), "dBm"));
            for (key, unit) in keys {
                if self.discovered.insert((id.clone(), key.clone())) {
                    let (t, c) = ha::entity(
                        &self.config.homeassistant.discovery_prefix,
                        &self.base,
                        &id,
                        &name,
                        &model,
                        manufacturer,
                        &key,
                        unit,
                    );
                    self.mqtt.publish_json(t, &c, true);
                }
            }
        }
    }

    async fn on_message(&mut self, topic: &str, payload: &[u8]) {
        if topic == self.config.homeassistant.status_topic {
            if HomeAssistantStatus::parse(payload) == Some(HomeAssistantState::Online) {
                // Home Assistant restarted: discovery again.
                self.discovered.clear();
            }
            return;
        }
        let Some(op) = topic
            .strip_prefix(&format!("{}/bridge/request/", self.base))
            .map(str::to_string)
        else {
            return;
        };
        let reply = format!("{}/bridge/response/{op}", self.base);
        let body: Json = if payload.is_empty() {
            Json::Object(Default::default())
        } else {
            match serde_json::from_slice(payload) {
                Ok(v) => v,
                Err(e) => {
                    let r = ErrorResponse::new(format!("the request is not JSON: {e}"), None);
                    self.mqtt.publish_json(reply, &r, false);
                    return;
                }
            }
        };
        let mqtt = self.mqtt.clone();
        if let Some(mesh_op) = op.strip_prefix("mesh/") {
            let Some(mesh) = self.mesh.clone() else {
                let r = ErrorResponse::new(
                    "the mesh is off ([mesh] enabled)".into(),
                    transaction(&body),
                );
                self.mqtt.publish_json(reply, &r, false);
                return;
            };
            let mesh_op = mesh_op.to_string();
            tokio::spawn(async move {
                let r = mesh.request(&mesh_op, &body).await;
                mqtt.publish(reply, r, false);
            });
            return;
        }
        // A scan started by request keeps hearing the mesh.
        let always_report = if self.config.mesh.enabled {
            crate::mesh::AD_TYPES.to_vec()
        } else {
            Vec::new()
        };
        // Requests that wait on the radio run on their own so scanning keeps flowing.
        let host = self.host.clone();
        tokio::spawn(async move {
            let r = request(&host, &op, &body, &always_report).await;
            mqtt.publish(reply, r, false);
        });
    }
}

/// The request's `transaction`, if it has one.
pub(crate) fn transaction(body: &Json) -> Option<Json> {
    body.get("transaction").filter(|t| !t.is_null()).cloned()
}

/// Reads a request as `Q`, runs it, and serializes its response `R`, with
/// the request's `transaction`.
pub(crate) async fn answer<Q, R>(
    body: &Json,
    run: impl AsyncFnOnce(Q) -> Result<R::Data, String>,
) -> Vec<u8>
where
    Q: DeserializeOwned,
    R: Response,
{
    let result = match serde_json::from_value::<Q>(body.clone()) {
        Ok(q) => run(q).await,
        Err(e) => Err(e.to_string()),
    };
    serde_json::to_vec(&R::new(result, transaction(body))).unwrap_or_default()
}

/// Decodes a hex field.
pub(crate) fn unhex(name: &str, s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("`{name}`: {e}"))
}

fn names(v: Vec<&'static str>) -> Vec<String> {
    v.into_iter().map(str::to_string).collect()
}

fn conn(host: &Host, handle: u16) -> Result<Connection, String> {
    host.connection(handle)
        .ok_or_else(|| format!("no connection {handle}"))
}

/// Runs one request and returns its response, serialized. A scan it
/// starts always reports `always_report`'s AD types too.
pub async fn request(host: &Host, op: &str, body: &Json, always_report: &[u8]) -> Vec<u8> {
    let e = |x: bluetooth_host::Error| x.to_string();
    match op {
        "info" => {
            answer::<EmptyRequest, InfoResponse>(body, async |_| {
                let c = host.capabilities();
                Ok(InfoData {
                    address: host.address(),
                    controller: c.clone(),
                    le_features: names(c.le_feature_names()),
                })
            })
            .await
        }
        "scan/start" => {
            answer::<ScanStartRequest, DoneResponse>(body, async |q| {
                let mut c = q.config.unwrap_or_default();
                for t in always_report {
                    if !c.always_report.contains(t) {
                        c.always_report.push(*t);
                    }
                }
                host.start_scan(c).await.map_err(e)?;
                Ok(Done {})
            })
            .await
        }
        "scan/stop" => {
            answer::<EmptyRequest, DoneResponse>(body, async |_| {
                host.stop_scan().await.map_err(e)?;
                Ok(Done {})
            })
            .await
        }
        "connect" => {
            answer::<ConnectRequest, ConnectResponse>(body, async |q| {
                let c = host
                    .connect(q.address, &q.params.unwrap_or_default())
                    .await
                    .map_err(e)?;
                Ok(ConnectData {
                    handle: c.handle(),
                    params: c.params(),
                })
            })
            .await
        }
        "disconnect" => {
            answer::<HandleRequest, DoneResponse>(body, async |q| {
                conn(host, q.handle)?.disconnect().await.map_err(e)?;
                Ok(Done {})
            })
            .await
        }
        "connections" => {
            answer::<EmptyRequest, ConnectionsResponse>(body, async |_| {
                Ok(host
                    .connections()
                    .iter()
                    .map(|c| ConnectionInfo {
                        handle: c.handle(),
                        address: c.peer(),
                        identity: c.identity(),
                        role: c.role(),
                        params: c.params(),
                        security: c.security(),
                        mtu: c.att_mtu(),
                    })
                    .collect())
            })
            .await
        }
        "connection/params" => {
            answer::<ConnectionParamsRequest, ConnectionParamsResponse>(body, async |q| {
                conn(host, q.handle)?
                    .update_params(q.params)
                    .await
                    .map_err(e)
            })
            .await
        }
        "connection/phy" => {
            answer::<ConnectionPhyRequest, ConnectionPhyResponse>(body, async |q| {
                let (tx, rx) = conn(host, q.handle)?
                    .set_phy(&q.tx, &q.rx, q.coded_s8)
                    .await
                    .map_err(e)?;
                Ok(PhyData { tx, rx })
            })
            .await
        }
        "connection/data_length" => {
            answer::<ConnectionDataLengthRequest, DoneResponse>(body, async |q| {
                conn(host, q.handle)?
                    .set_data_length(q.tx_octets, q.tx_time)
                    .await
                    .map_err(e)?;
                Ok(Done {})
            })
            .await
        }
        "connection/rssi" => {
            answer::<HandleRequest, ConnectionRssiResponse>(body, async |q| {
                Ok(RssiData {
                    rssi: conn(host, q.handle)?.read_rssi().await.map_err(e)?,
                })
            })
            .await
        }
        "gatt/mtu" => {
            answer::<GattMtuRequest, GattMtuResponse>(body, async |q| {
                Ok(MtuData {
                    mtu: conn(host, q.handle)?
                        .gatt()
                        .exchange_mtu(q.mtu)
                        .await
                        .map_err(e)?,
                })
            })
            .await
        }
        "gatt/discover" => {
            answer::<HandleRequest, GattDiscoverResponse>(body, async |q| {
                conn(host, q.handle)?.gatt().discover().await.map_err(e)
            })
            .await
        }
        "gatt/read" => {
            answer::<GattReadRequest, GattReadResponse>(body, async |q| {
                let v = conn(host, q.handle)?
                    .gatt()
                    .read(q.attribute)
                    .await
                    .map_err(e)?;
                Ok(ValueData {
                    value: hex::encode(v),
                })
            })
            .await
        }
        "gatt/write" => {
            answer::<GattWriteRequest, DoneResponse>(body, async |q| {
                let v = unhex("value", &q.value)?;
                let g = conn(host, q.handle)?.gatt();
                if q.without_response {
                    g.write_without_response(q.attribute, &v).await.map_err(e)?;
                } else {
                    g.write(q.attribute, &v).await.map_err(e)?;
                }
                Ok(Done {})
            })
            .await
        }
        "gatt/subscribe" => {
            answer::<GattSubscribeRequest, DoneResponse>(body, async |q| {
                let g = conn(host, q.handle)?.gatt();
                let c = g.characteristic_at(q.attribute).await.map_err(e)?;
                g.subscribe(&c, q.notify, q.indicate).await.map_err(e)?;
                Ok(Done {})
            })
            .await
        }
        "pair" => {
            answer::<HandleRequest, SecurityResponse>(body, async |q| {
                conn(host, q.handle)?.pair().await.map_err(e)
            })
            .await
        }
        "secure" => {
            answer::<HandleRequest, SecurityResponse>(body, async |q| {
                conn(host, q.handle)?.secure().await.map_err(e)
            })
            .await
        }
        "unpair" => {
            answer::<UnpairRequest, UnpairResponse>(body, async |q| {
                Ok(UnpairData {
                    removed: host.keys().remove(&q.address).map_err(e)?,
                })
            })
            .await
        }
        "bonds" => {
            answer::<EmptyRequest, BondsResponse>(body, async |_| {
                Ok(host
                    .keys()
                    .bonds()
                    .iter()
                    // Never publish keys: only who, and what kind of bond.
                    .map(|b| BondInfo {
                        identity: b.identity,
                        label: b.label.clone(),
                        has_ltk: b.ltk.is_some(),
                        has_irk: b.irk.is_some(),
                        authenticated: b.authenticated,
                        secure_connections: b.secure_connections,
                    })
                    .collect())
            })
            .await
        }
        "advertise/start" => {
            answer::<AdvertiseStartRequest, AdvertiseStartResponse>(body, async |q| {
                let set = host
                    .advertise(
                        &q.params.unwrap_or_default(),
                        &unhex("data", &q.data)?,
                        &unhex("scan_response", &q.scan_response)?,
                    )
                    .await
                    .map_err(e)?;
                Ok(SetData { set })
            })
            .await
        }
        "advertise/data" => {
            answer::<AdvertiseDataRequest, DoneResponse>(body, async |q| {
                let sr = q
                    .scan_response
                    .as_deref()
                    .map(|s| unhex("scan_response", s))
                    .transpose()?;
                host.set_advertising_data(q.set, &unhex("data", &q.data)?, sr.as_deref())
                    .await
                    .map_err(e)?;
                Ok(Done {})
            })
            .await
        }
        "advertise/stop" => {
            answer::<SetRequest, DoneResponse>(body, async |q| {
                host.stop_advertising(q.set).await.map_err(e)?;
                Ok(Done {})
            })
            .await
        }
        "periodic/start" => {
            answer::<PeriodicStartRequest, DoneResponse>(body, async |q| {
                host.start_periodic(
                    q.set,
                    &q.params.unwrap_or_default(),
                    &unhex("data", &q.data)?,
                )
                .await
                .map_err(e)?;
                Ok(Done {})
            })
            .await
        }
        "periodic/stop" => {
            answer::<SetRequest, DoneResponse>(body, async |q| {
                host.stop_periodic(q.set).await.map_err(e)?;
                Ok(Done {})
            })
            .await
        }
        "periodic/sync" => {
            answer::<PeriodicSyncRequest, PeriodicSyncResponse>(body, async |q| {
                let sync = host
                    .sync_periodic(q.address, q.sid, q.skip, q.timeout_ms.unwrap_or(5000))
                    .await
                    .map_err(e)?;
                Ok(SyncData { sync })
            })
            .await
        }
        "periodic/terminate" => {
            answer::<PeriodicTerminateRequest, DoneResponse>(body, async |q| {
                host.terminate_sync(q.sync).await.map_err(e)?;
                Ok(Done {})
            })
            .await
        }
        "server/add" => {
            answer::<ServerAddRequest, ServerAddResponse>(body, async |q| {
                host.gatt_server().add(&q.service).await.map_err(e)
            })
            .await
        }
        "server/set" => {
            answer::<ServerSetRequest, ServerSetResponse>(body, async |q| {
                let v = unhex("value", &q.value)?;
                let server = host.gatt_server();
                if q.notify {
                    Ok(ServerSetData {
                        notified: Some(server.notify(q.attribute, &v).await.map_err(e)?),
                    })
                } else {
                    server.set(q.attribute, &v).map_err(e)?;
                    Ok(ServerSetData::default())
                }
            })
            .await
        }
        "server/get" => {
            answer::<ServerGetRequest, ServerGetResponse>(body, async |q| {
                Ok(ServerValueData {
                    value: host.gatt_server().value(q.attribute).map(hex::encode),
                })
            })
            .await
        }
        other => {
            let r = ErrorResponse::new(format!("unknown request {other:?}"), transaction(body));
            serde_json::to_vec(&r).unwrap_or_default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_prefixes() {
        let a: Address = "BC:57:29:00:00:01".parse().unwrap();
        assert_eq!(topic_id(&a), "BC5729000001");
        assert_eq!(parse_prefix("BC:57:29"), vec![0xbc, 0x57, 0x29]);
        assert_eq!(parse_prefix("bc5"), vec![0xbc]);
    }
}
