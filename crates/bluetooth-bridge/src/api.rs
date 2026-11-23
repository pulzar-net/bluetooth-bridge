//! The MQTT API: every payload the bridge publishes or reads, as a type.
//!
//! The bridge serializes these and nothing else, so they are the contract.
//! With the `unstable-asyncapi-docs` feature each one also derives a JSON
//! Schema and an AsyncAPI message, and `tests/asyncapi.rs` assembles them
//! into the AsyncAPI description the docs site renders as the MQTT
//! reference. That feature is docs tooling, not API: it may change in any
//! release, and the bridge's own builds never turn it on.
//!
//! Topics are under the base topic (`mqtt.base_topic`, default `bluetooth`).
//! `<ADDRESS>` is a device's address as twelve upper-case hex digits, most
//! significant first (`BC5729000001`). Byte strings (advertising data,
//! attribute values) are lower-case hex. Keys never appear on MQTT.

use bluetooth_adv::beacon::Beacon;
use bluetooth_adv::Advertisement;
use bluetooth_host::controller::Capabilities;
use bluetooth_host::gatt::server::{ServiceDef, ServiceHandles};
use bluetooth_host::gatt::Service;
use bluetooth_host::{
    Address, AdvertisingParams, ConnParams, ConnectParams, ParamsRequest, PeriodicParams,
    PeriodicReport, Phy, Report, Role, ScanConfig, Security,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

#[cfg(feature = "unstable-asyncapi-docs")]
use asyncapi_rust::ToAsyncApiMessage;
#[cfg(feature = "unstable-asyncapi-docs")]
use schemars::JsonSchema;

// ---------------------------------------------------------------------------
// Availability

/// The bridge's availability, retained on `bridge/state`. The broker
/// publishes `offline` as the bridge's last will when the connection drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    derive(JsonSchema, ToAsyncApiMessage)
)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    asyncapi(summary = "The bridge is online or offline")
)]
pub struct BridgeState {
    /// `online` while the bridge runs, `offline` once it stops or its
    /// connection drops.
    pub state: Availability,
}

/// Online or offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    /// Running, with its controller open.
    Online,
    /// Stopped, or the MQTT connection dropped.
    Offline,
}

impl BridgeState {
    /// The availability as the payload the bridge publishes.
    pub fn payload(state: Availability) -> Vec<u8> {
        serde_json::to_vec(&BridgeState { state }).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Bridge info

/// The bridge and its controller, retained on `bridge/info`, published on
/// connecting to the broker.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    derive(JsonSchema, ToAsyncApiMessage)
)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    asyncapi(summary = "The bridge's version and its controller")
)]
pub struct BridgeInfo {
    /// The bridge's version.
    pub version: String,
    /// The address the bridge advertises and connects from.
    pub address: Address,
    /// The controller's versions, buffers and feature masks.
    pub controller: Capabilities,
    /// The controller's manufacturer, by the Bluetooth SIG's company name,
    /// when known.
    pub manufacturer_name: Option<String>,
    /// The Core Specification version the controller implements (`5.3`),
    /// when known.
    pub core_version: Option<String>,
    /// The LE features the controller supports, by name.
    pub le_features: Vec<String>,
    /// The transport, as configured (`adapter.transport`): `hci0`,
    /// `serial:/dev/ttyACM0`, ...
    pub transport: String,
}

// ---------------------------------------------------------------------------
// Advertisements and readings

/// An advertisement, after duplicate filtering, on `scan/<ADDRESS>`. Only
/// with `scan.publish_reports`; `<ADDRESS>` is the identity when a stored
/// IRK resolves a private address.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    derive(JsonSchema, ToAsyncApiMessage)
)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    asyncapi(summary = "An advertisement, parsed and decoded")
)]
pub struct ScanReport {
    /// The report as the controller gave it.
    #[serde(flatten)]
    pub report: Report,
    /// The advertising data and scan response, parsed.
    pub advertisement: Advertisement,
    /// The device's local name, when it sent one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Beacon and sensor frames decoded from it (iBeacon, AltBeacon,
    /// Eddystone, BTHome, KKM, Ruuvi).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub beacons: Vec<Beacon>,
}

/// A device's decoded readings, on `device/<ADDRESS>`, published after each
/// advertisement that has any. Home Assistant reads its entities from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    derive(JsonSchema, ToAsyncApiMessage)
)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    asyncapi(summary = "A device's readings")
)]
pub struct DeviceState {
    /// Each reading by its key, in the unit the beacon format defines:
    /// `temperature` (°C), `humidity` (%), `battery` (%), `button_2`, ...
    #[serde(flatten)]
    pub readings: Map<String, Json>,
    /// Received signal strength of the advertisement, dBm.
    pub rssi: i8,
    /// When it was received, milliseconds since the Unix epoch.
    pub last_seen: u64,
}

// ---------------------------------------------------------------------------
// Events

/// Something happened on the radio, on `bridge/event`: a connection, a
/// pairing, a notification, a write to the bridge's GATT server, a periodic
/// advertising report. `type` names it.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    derive(JsonSchema, ToAsyncApiMessage)
)]
#[serde(tag = "type")]
pub enum BridgeEvent {
    /// A connection opened, in either role.
    #[serde(rename = "connected")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "A connection opened")
    )]
    Connected {
        /// The connection handle, which requests on it name.
        handle: u16,
        /// The peer's address as connected.
        address: Address,
        /// The peer's identity address (its address unless resolved).
        identity: Address,
        /// The bridge's role.
        role: Role,
    },
    /// A connection closed.
    #[serde(rename = "disconnected")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "A connection closed")
    )]
    Disconnected {
        /// The connection handle.
        handle: u16,
        /// The peer, as connected.
        address: Address,
        /// The HCI reason code.
        reason: u8,
        /// The reason code's name.
        reason_name: String,
    },
    /// Pairing finished.
    #[serde(rename = "paired")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "Pairing finished")
    )]
    Paired {
        /// The connection handle.
        handle: u16,
        /// The peer's identity address.
        identity: Address,
        /// The keys were stored.
        bonded: bool,
        /// The link's security now.
        security: Security,
        /// LE security mode 1 level: 1 none, 2 unauthenticated encryption,
        /// 3 authenticated, 4 authenticated Secure Connections with a
        /// 128-bit key.
        level: u8,
    },
    /// Pairing failed.
    #[serde(rename = "pairing_failed")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "Pairing failed")
    )]
    PairingFailed {
        /// The connection handle.
        handle: u16,
        /// Why.
        reason: String,
    },
    /// A client wrote one of the bridge's GATT server's characteristics.
    #[serde(rename = "gatt_write")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "A client wrote one of the bridge's characteristics")
    )]
    GattWrite {
        /// The connection handle.
        handle: u16,
        /// The attribute handle.
        attribute: u16,
        /// The value written, hex.
        value: String,
    },
    /// A client turned notifications or indications on or off for one of
    /// the bridge's characteristics.
    #[serde(rename = "gatt_subscription")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "A client subscribed or unsubscribed")
    )]
    GattSubscription {
        /// The connection handle.
        handle: u16,
        /// The characteristic value's handle.
        attribute: u16,
        /// Notifications are on.
        notify: bool,
        /// Indications are on.
        indicate: bool,
    },
    /// A peer's characteristic notified or indicated.
    #[serde(rename = "notification")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "A peer's characteristic notified")
    )]
    Notification {
        /// The connection handle.
        handle: u16,
        /// The characteristic value's handle.
        attribute: u16,
        /// The value, hex.
        value: String,
        /// An indication (already confirmed) rather than a notification.
        indication: bool,
    },
    /// A connection's parameters, PHY, data length, security or MTU changed.
    #[serde(rename = "connection")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "A connection's parameters, PHY or security changed")
    )]
    ConnectionChanged {
        /// The connection handle.
        handle: u16,
        /// What changed, as the host describes it.
        change: String,
    },
    /// A report from a synchronized periodic advertising train.
    #[serde(rename = "periodic_report")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "A periodic advertising report")
    )]
    PeriodicReport {
        /// The report.
        report: PeriodicReport,
        /// Its data, parsed.
        advertisement: Box<Advertisement>,
    },
    /// A periodic advertising train was lost.
    #[serde(rename = "periodic_sync_lost")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "A periodic advertising train was lost")
    )]
    PeriodicSyncLost {
        /// The sync handle.
        sync: u16,
    },
    /// An advertising set stopped: its duration ran out, it reached its
    /// event count, or (connectable) someone connected.
    #[serde(rename = "advertising_stopped")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "An advertising set stopped")
    )]
    AdvertisingStopped {
        /// The set.
        set: u8,
        /// The connection it made, if any.
        connection: Option<u16>,
    },
    /// A scanner sent a scan request to one of the bridge's sets.
    #[serde(rename = "scan_request")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "A scanner sent a scan request")
    )]
    ScanRequest {
        /// The set.
        set: u8,
        /// Who asked.
        scanner: Address,
    },
}

/// Something happened in the mesh, on `mesh/event`. Only with
/// `mesh.enabled`. `type` names it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    derive(JsonSchema, ToAsyncApiMessage)
)]
#[serde(tag = "type")]
pub enum MeshEvent {
    /// An unprovisioned device's beacon was heard for the first time since
    /// the bridge started.
    #[serde(rename = "unprovisioned")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "An unprovisioned device was heard")
    )]
    Unprovisioned {
        /// Its Device UUID, hex.
        uuid: String,
        /// Its OOB Information field: how it can show or take
        /// authentication data.
        oob_info: u16,
    },
    /// An access message to the bridge.
    #[serde(rename = "message")]
    #[cfg_attr(
        feature = "unstable-asyncapi-docs",
        asyncapi(summary = "An access message to the bridge")
    )]
    AccessMessage {
        /// The sender's unicast address.
        src: u16,
        /// The destination: the bridge, or a group it subscribes to.
        dst: u16,
        /// The opcode, as the stack names it.
        opcode: String,
        /// The parameters, hex.
        params: String,
    },
}

// ---------------------------------------------------------------------------
// Requests and responses

/// `ok` or `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Done; `data` has the result.
    Ok,
    /// Not done; `error` says why.
    Error,
}

/// A response: built from a request's result and its `transaction`.
pub trait Response: Serialize {
    /// What `data` holds.
    type Data;
    /// The response to a request with `transaction`.
    fn new(result: Result<Self::Data, String>, transaction: Option<Json>) -> Self;
}

macro_rules! response {
    ($(#[$doc:meta])* $name:ident, $data:ty, $summary:literal) => {
        $(#[$doc])*
        ///
        /// A response is published once per request, to
        /// `bridge/response/<request>`, and is not retained.
        #[derive(Debug, Clone, Serialize)]
        #[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema, ToAsyncApiMessage))]
        #[cfg_attr(feature = "unstable-asyncapi-docs", asyncapi(summary = $summary))]
        pub struct $name {
            /// `ok` or `error`.
            pub status: Status,
            /// The result, when `status` is `ok`.
            #[serde(skip_serializing_if = "Option::is_none")]
            pub data: Option<$data>,
            /// What went wrong, when `status` is `error`.
            #[serde(skip_serializing_if = "Option::is_none")]
            pub error: Option<String>,
            /// The request's `transaction`, echoed when it had one.
            #[serde(skip_serializing_if = "Option::is_none")]
            pub transaction: Option<Json>,
        }

        impl Response for $name {
            type Data = $data;
            fn new(result: Result<$data, String>, transaction: Option<Json>) -> Self {
                match result {
                    Ok(data) => $name { status: Status::Ok, data: Some(data), error: None, transaction },
                    Err(error) => $name { status: Status::Error, data: None, error: Some(error), transaction },
                }
            }
        }
    };
}

macro_rules! request {
    ($(#[$doc:meta])* $name:ident, $summary:literal { $($(#[$fattr:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema, ToAsyncApiMessage))]
        #[cfg_attr(feature = "unstable-asyncapi-docs", asyncapi(summary = $summary))]
        pub struct $name {
            $($(#[$fattr])* pub $field: $ty,)*
            /// Any value; the response echoes it, so a client can match the
            /// two.
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub transaction: Option<Json>,
        }
    };
}

/// An empty result: the request is done.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct Done {}

// Shapes several requests and responses share: one type each, so the
// bridge carries one serde implementation for all of them.

request!(
    /// A request with no fields: `info`, `scan/stop`, `connections`,
    /// `bonds`, `mesh/network`, `mesh/unprovisioned`. An empty payload is
    /// the same as `{}`.
    EmptyRequest, "A request with no fields" {}
);

request!(
    /// A request on one connection: `disconnect`, `connection/rssi`,
    /// `gatt/discover`, `pair`, `secure`.
    HandleRequest, "A request on a connection" {
        /// The connection handle.
        handle: u16,
    }
);

request!(
    /// A request on one advertising set: `advertise/stop`, `periodic/stop`.
    SetRequest, "A request on an advertising set" {
        /// The set.
        set: u8,
    }
);

response!(
    /// The response to a request that is done once the controller has it:
    /// `scan/start`, `scan/stop`, `disconnect`, `connection/data_length`,
    /// `gatt/write`, `gatt/subscribe`, `advertise/data`, `advertise/stop`,
    /// `periodic/start`, `periodic/stop`, `periodic/terminate`.
    DoneResponse,
    Done,
    "The request is done"
);

response!(
    /// The response to `pair` and `secure`: the link's security.
    SecurityResponse,
    Security,
    "The link's security"
);

// Controller and scanning.

/// The result of `info`.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct InfoData {
    /// The address the bridge advertises and connects from.
    pub address: Address,
    /// The controller's versions, buffers and feature masks.
    pub controller: Capabilities,
    /// The LE features the controller supports, by name.
    pub le_features: Vec<String>,
}

response!(
    /// The response to `info`.
    InfoResponse,
    InfoData,
    "The controller"
);

request!(
    /// Start scanning, or restart with another configuration, on
    /// `bridge/request/scan/start`.
    ScanStartRequest, "Start scanning" {
        /// The scan, as in the configuration's `[scan.config]`; the defaults
        /// when absent. With the mesh on, the mesh's AD types are always
        /// reported.
        #[serde(default)]
        config: Option<ScanConfig>,
    }
);

// Connections.

request!(
    /// Connect to a device as central, on `bridge/request/connect`.
    ConnectRequest, "Connect to a device" {
        /// The device's address, with `/random` for a random one.
        address: Address,
        /// Connection parameters; the defaults when absent.
        #[serde(default)]
        params: Option<ConnectParams>,
    }
);

/// The result of `connect`.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct ConnectData {
    /// The connection handle, which requests on the connection name.
    pub handle: u16,
    /// The parameters the controller chose.
    pub params: ConnParams,
}

response!(
    /// The response to `connect`.
    ConnectResponse,
    ConnectData,
    "The device is connected"
);

/// An open connection.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct ConnectionInfo {
    /// The connection handle.
    pub handle: u16,
    /// The peer's address as connected.
    pub address: Address,
    /// The peer's identity address.
    pub identity: Address,
    /// The bridge's role.
    pub role: Role,
    /// The connection parameters.
    pub params: ConnParams,
    /// How secure the link is.
    pub security: Security,
    /// The ATT MTU.
    pub mtu: u16,
}

response!(
    /// The response to `connections`.
    ConnectionsResponse,
    Vec<ConnectionInfo>,
    "The open connections"
);

request!(
    /// Ask for new connection parameters, on
    /// `bridge/request/connection/params`.
    ConnectionParamsRequest, "Change a connection's parameters" {
        /// The connection handle.
        handle: u16,
        /// The parameters wanted.
        params: ParamsRequest,
    }
);

response!(
    /// The response to `connection/params`.
    ConnectionParamsResponse,
    ConnParams,
    "The parameters now in use"
);

request!(
    /// Ask for other PHYs, on `bridge/request/connection/phy`.
    ConnectionPhyRequest, "Change a connection's PHYs" {
        /// The connection handle.
        handle: u16,
        /// The PHYs the bridge may send on, most wanted first.
        tx: Vec<Phy>,
        /// The PHYs the bridge may receive on.
        rx: Vec<Phy>,
        /// On the coded PHY, S=8 coding rather than S=2.
        #[serde(default)]
        coded_s8: bool,
    }
);

/// The result of `connection/phy`.
#[derive(Debug, Clone, Copy, Serialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct PhyData {
    /// The PHY the bridge sends on.
    pub tx: Phy,
    /// The PHY the bridge receives on.
    pub rx: Phy,
}

response!(
    /// The response to `connection/phy`.
    ConnectionPhyResponse,
    PhyData,
    "The PHYs now in use"
);

request!(
    /// Set the largest packets the bridge sends, on
    /// `bridge/request/connection/data_length`.
    ConnectionDataLengthRequest, "Change a connection's data length" {
        /// The connection handle.
        handle: u16,
        /// Octets per packet, 27 to 251.
        tx_octets: u16,
        /// Microseconds per packet, 328 to 17040.
        tx_time: u16,
    }
);

/// The result of `connection/rssi`.
#[derive(Debug, Clone, Copy, Serialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct RssiData {
    /// Received signal strength, dBm.
    pub rssi: i8,
}

response!(
    /// The response to `connection/rssi`.
    ConnectionRssiResponse,
    RssiData,
    "The connection's signal strength"
);

// GATT client.

request!(
    /// Exchange the ATT MTU, on `bridge/request/gatt/mtu`.
    GattMtuRequest, "Exchange the ATT MTU" {
        /// The connection handle.
        handle: u16,
        /// The MTU the bridge can take.
        mtu: u16,
    }
);

/// The result of `gatt/mtu`.
#[derive(Debug, Clone, Copy, Serialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct MtuData {
    /// The MTU now in use.
    pub mtu: u16,
}

response!(
    /// The response to `gatt/mtu`.
    GattMtuResponse,
    MtuData,
    "The ATT MTU now in use"
);

response!(
    /// The response to `gatt/discover`.
    GattDiscoverResponse,
    Vec<Service>,
    "The peer's services"
);

request!(
    /// Read a peer's attribute, on `bridge/request/gatt/read`. Long values
    /// are read in full.
    GattReadRequest, "Read an attribute" {
        /// The connection handle.
        handle: u16,
        /// The attribute handle.
        attribute: u16,
    }
);

/// An attribute value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct ValueData {
    /// The value, hex.
    pub value: String,
}

response!(
    /// The response to `gatt/read`.
    GattReadResponse,
    ValueData,
    "The attribute's value"
);

request!(
    /// Write a peer's attribute, on `bridge/request/gatt/write`.
    GattWriteRequest, "Write an attribute" {
        /// The connection handle.
        handle: u16,
        /// The attribute handle.
        attribute: u16,
        /// The value, hex.
        #[serde(default)]
        value: String,
        /// A Write Command, unacknowledged, rather than a Write Request.
        #[serde(default)]
        without_response: bool,
    }
);

request!(
    /// Turn a peer characteristic's notifications or indications on or off,
    /// on `bridge/request/gatt/subscribe`. They arrive as `notification`
    /// events.
    GattSubscribeRequest, "Subscribe to a characteristic" {
        /// The connection handle.
        handle: u16,
        /// The characteristic value's handle.
        attribute: u16,
        /// Notifications on.
        #[serde(default)]
        notify: bool,
        /// Indications on.
        #[serde(default)]
        indicate: bool,
    }
);

// Security.

request!(
    /// Forget a bond, on `bridge/request/unpair`.
    UnpairRequest, "Forget a bond" {
        /// The peer's identity address.
        address: Address,
    }
);

/// The result of `unpair`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct UnpairData {
    /// A bond was stored and is gone.
    pub removed: bool,
}

response!(
    /// The response to `unpair`.
    UnpairResponse,
    UnpairData,
    "The bond is forgotten"
);

/// A stored bond: who, and what kind of keys, never the keys.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct BondInfo {
    /// The peer's identity address.
    pub identity: Address,
    /// The label it was stored with, if any.
    pub label: Option<String>,
    /// A long-term key is stored.
    pub has_ltk: bool,
    /// The peer's identity resolving key is stored.
    pub has_irk: bool,
    /// The keys came from a pairing with MITM protection.
    pub authenticated: bool,
    /// The keys came from LE Secure Connections.
    pub secure_connections: bool,
}

response!(
    /// The response to `bonds`.
    BondsResponse,
    Vec<BondInfo>,
    "The stored bonds"
);

// Advertising.

request!(
    /// Start an advertising set, on `bridge/request/advertise/start`.
    AdvertiseStartRequest, "Start advertising" {
        /// The set's parameters; the defaults when absent.
        #[serde(default)]
        params: Option<AdvertisingParams>,
        /// The advertising data, hex.
        #[serde(default)]
        data: String,
        /// The scan response, hex.
        #[serde(default)]
        scan_response: String,
    }
);

/// An advertising set.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct SetData {
    /// The set's handle, which later requests on it name.
    pub set: u8,
}

response!(
    /// The response to `advertise/start`.
    AdvertiseStartResponse,
    SetData,
    "The advertising set started"
);

request!(
    /// Change a set's data while it advertises, on
    /// `bridge/request/advertise/data`.
    AdvertiseDataRequest, "Change a set's advertising data" {
        /// The set.
        set: u8,
        /// The advertising data, hex.
        #[serde(default)]
        data: String,
        /// The scan response, hex; unchanged when absent.
        #[serde(default)]
        scan_response: Option<String>,
    }
);

request!(
    /// Start periodic advertising on an extended set, on
    /// `bridge/request/periodic/start`.
    PeriodicStartRequest, "Start periodic advertising" {
        /// The set.
        set: u8,
        /// The train's parameters; the defaults when absent.
        #[serde(default)]
        params: Option<PeriodicParams>,
        /// The periodic data, hex.
        #[serde(default)]
        data: String,
    }
);

request!(
    /// Synchronize to another device's periodic advertising train, on
    /// `bridge/request/periodic/sync`. Its reports arrive as
    /// `periodic_report` events.
    PeriodicSyncRequest, "Follow a periodic advertising train" {
        /// The advertiser.
        address: Address,
        /// Its advertising set id.
        sid: u8,
        /// Periodic events the controller may skip.
        #[serde(default)]
        skip: u16,
        /// Milliseconds without a report before the sync is lost; 5000
        /// when absent.
        #[serde(default)]
        timeout_ms: Option<u32>,
    }
);

/// A periodic advertising sync.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct SyncData {
    /// The sync handle.
    pub sync: u16,
}

response!(
    /// The response to `periodic/sync`.
    PeriodicSyncResponse,
    SyncData,
    "The train is followed"
);

request!(
    /// Stop following a periodic advertising train, on
    /// `bridge/request/periodic/terminate`.
    PeriodicTerminateRequest, "Stop following a train" {
        /// The sync handle.
        sync: u16,
    }
);

// GATT server.

request!(
    /// Add a service to the bridge's GATT server, on
    /// `bridge/request/server/add`.
    ServerAddRequest, "Add a GATT service" {
        /// The service, as in the configuration's `[[gatt_services]]`.
        service: ServiceDef,
    }
);

response!(
    /// The response to `server/add`.
    ServerAddResponse,
    ServiceHandles,
    "The service's handles"
);

request!(
    /// Set a value in the bridge's GATT server, on
    /// `bridge/request/server/set`.
    ServerSetRequest, "Set a characteristic's value" {
        /// The attribute handle.
        attribute: u16,
        /// The value, hex.
        #[serde(default)]
        value: String,
        /// Also notify or indicate every subscribed client.
        #[serde(default)]
        notify: bool,
    }
);

/// The result of `server/set`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct ServerSetData {
    /// How many clients were notified or indicated, with `notify`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notified: Option<usize>,
}

response!(
    /// The response to `server/set`.
    ServerSetResponse,
    ServerSetData,
    "The value is set"
);

request!(
    /// Read a value from the bridge's GATT server, on
    /// `bridge/request/server/get`.
    ServerGetRequest, "Read a characteristic's value" {
        /// The attribute handle.
        attribute: u16,
    }
);

/// The result of `server/get`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct ServerValueData {
    /// The value, hex, or `null` when there is no such attribute.
    pub value: Option<String>,
}

response!(
    /// The response to `server/get`.
    ServerGetResponse,
    ServerValueData,
    "The value"
);

// Mesh.

/// A node the bridge provisioned.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct MeshNode {
    /// Its Device UUID, hex.
    pub uuid: String,
    /// Its primary element's unicast address.
    pub address: u16,
    /// How many elements it has (addresses `address` onwards).
    pub elements: u8,
}

/// The result of `mesh/network`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct MeshNetworkData {
    /// The bridge's unicast address.
    pub address: u16,
    /// The IV index.
    pub iv_index: u32,
    /// The nodes the bridge provisioned.
    pub nodes: Vec<MeshNode>,
}

response!(
    /// The response to `mesh/network`.
    MeshNetworkResponse,
    MeshNetworkData,
    "The mesh network"
);

/// An unprovisioned device whose beacon was heard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct UnprovisionedDevice {
    /// Its Device UUID, hex.
    pub uuid: String,
    /// Its OOB Information field.
    pub oob_info: u16,
    /// When its beacon was last heard, seconds since the Unix epoch.
    pub heard: u64,
}

response!(
    /// The response to `mesh/unprovisioned`.
    MeshUnprovisionedResponse,
    Vec<UnprovisionedDevice>,
    "The unprovisioned devices heard"
);

request!(
    /// Provision a device into the network, on
    /// `bridge/request/mesh/provision`. Waits up to two minutes.
    MeshProvisionRequest, "Provision a device" {
        /// Its Device UUID, 16 octets in hex.
        uuid: String,
        /// Its static OOB value, 16 octets in hex, when it has one.
        #[serde(default)]
        static_oob: Option<String>,
    }
);

response!(
    /// The response to `mesh/provision`.
    MeshProvisionResponse,
    MeshNode,
    "The device is a node"
);

request!(
    /// Give a node the application key, bind its models and read its
    /// Composition Data, on `bridge/request/mesh/configure`. Waits up to a
    /// minute.
    MeshConfigureRequest, "Configure a node" {
        /// The node's unicast address.
        address: u16,
    }
);

/// A node's Composition Data, page 0.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct MeshComposition {
    /// Its company identifier.
    pub company: u16,
    /// The company, by the Bluetooth SIG's name, when known.
    pub company_name: Option<String>,
    /// Its product identifier.
    pub product: u16,
    /// Its version identifier.
    pub version: u16,
    /// The features it supports.
    pub features: MeshFeatures,
    /// Its elements, primary first.
    pub elements: Vec<MeshElement>,
}

/// A node's features.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct MeshFeatures {
    /// Relays messages.
    pub relay: bool,
    /// Is a GATT proxy.
    pub proxy: bool,
    /// Can be a friend to low-power nodes.
    pub friend: bool,
    /// Is a low-power node.
    pub low_power: bool,
}

/// An element of a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct MeshElement {
    /// Its location, a GATT Namespace Descriptor.
    pub location: u16,
    /// Its models.
    pub models: Vec<MeshModel>,
}

/// A model: a SIG model, or a vendor's.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
#[serde(untagged)]
pub enum MeshModel {
    /// A vendor model.
    Vendor {
        /// The vendor's company identifier.
        company: u16,
        /// The vendor, by the Bluetooth SIG's name, when known.
        company_name: Option<String>,
        /// The model id, four hex digits.
        id: String,
    },
    /// A Bluetooth SIG model.
    Sig {
        /// The model id, four hex digits.
        id: String,
        /// The SIG's name for it, when known.
        name: Option<String>,
    },
}

response!(
    /// The response to `mesh/configure`.
    MeshConfigureResponse,
    MeshComposition,
    "The node's composition"
);

request!(
    /// Switch a node's Generic OnOff server, on `bridge/request/mesh/onoff`.
    /// Waits up to 30 seconds for its status.
    MeshOnOffRequest, "Switch a node on or off" {
        /// The node's unicast address.
        address: u16,
        /// On or off.
        on: bool,
    }
);

/// The result of `mesh/onoff`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct OnOffData {
    /// The state the node reports.
    pub on: bool,
}

response!(
    /// The response to `mesh/onoff`.
    MeshOnOffResponse,
    OnOffData,
    "The node's state"
);

/// The response to a request the bridge could not read: not JSON, or not a
/// request it knows. Published on `bridge/response/<request>` like any
/// other response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    derive(JsonSchema, ToAsyncApiMessage)
)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    asyncapi(summary = "The request could not be read")
)]
pub struct ErrorResponse {
    /// `error`.
    pub status: Status,
    /// What went wrong.
    pub error: String,
    /// The request's `transaction`, echoed when the bridge could read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<Json>,
}

impl ErrorResponse {
    /// An error with the request's `transaction`.
    pub fn new(error: String, transaction: Option<Json>) -> Self {
        ErrorResponse {
            status: Status::Error,
            error,
            transaction,
        }
    }
}

// ---------------------------------------------------------------------------
// Home Assistant

/// Home Assistant's birth and last will, on `homeassistant.status_topic`.
/// `online` makes the bridge publish discovery again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    derive(JsonSchema, ToAsyncApiMessage)
)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    asyncapi(
        summary = "Home Assistant started or stopped",
        content_type = "text/plain"
    )
)]
#[serde(transparent)]
pub struct HomeAssistantStatus(pub HomeAssistantState);

/// Whether Home Assistant runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum HomeAssistantState {
    /// Home Assistant started.
    Online,
    /// Home Assistant stopped.
    Offline,
}

impl HomeAssistantStatus {
    /// The status in a payload, if it is one.
    pub fn parse(payload: &[u8]) -> Option<HomeAssistantState> {
        match payload {
            b"online" => Some(HomeAssistantState::Online),
            b"offline" => Some(HomeAssistantState::Offline),
            _ => None,
        }
    }
}

/// A Home Assistant MQTT discovery config, retained on
/// `<discovery_prefix>/<component>/<object>/<key>/config`: one entity per
/// reading of a device, and the bridge's own connection state. Keys are
/// Home Assistant's; see its MQTT integration documentation.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    derive(JsonSchema, ToAsyncApiMessage)
)]
#[cfg_attr(
    feature = "unstable-asyncapi-docs",
    asyncapi(summary = "A Home Assistant entity")
)]
pub struct DiscoveryConfig {
    /// The entity's name: the reading's key, with spaces.
    pub name: String,
    /// Unique across Home Assistant: `bluetooth_<address>_<key>`, or
    /// `<bridge>_connection_state` for the bridge.
    pub unique_id: String,
    /// The entity id Home Assistant derives, the same as `unique_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    /// The topic the state is on: the device's `device/<ADDRESS>`, or the
    /// bridge's `bridge/state`.
    pub state_topic: String,
    /// Picks the reading out of the state.
    pub value_template: String,
    /// The bridge's availability, for a device's entities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_topic: Option<String>,
    /// Picks `state` out of the availability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_template: Option<String>,
    /// The reading's unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_of_measurement: Option<String>,
    /// Home Assistant's device class for the reading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_class: Option<String>,
    /// `measurement`, or `total_increasing` for meters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_class: Option<String>,
    /// `diagnostic` for signal strength and the bridge's connection state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_category: Option<String>,
    /// `false` for signal strength: off until a person turns it on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_by_default: Option<bool>,
    /// The device the entity belongs to.
    pub device: DiscoveryDevice,
}

/// The device an entity belongs to.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "unstable-asyncapi-docs", derive(JsonSchema))]
pub struct DiscoveryDevice {
    /// `bluetooth_<address>`, or the bridge's own id.
    pub identifiers: Vec<String>,
    /// `[["bluetooth", "<address>"]]`, for a device.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<(String, String)>,
    /// The device's local name, or its address.
    pub name: String,
    /// The beacon format (`BTHome`, `Ruuvi`, ...), or `bluetooth-bridge`.
    pub model: String,
    /// The company in its manufacturer data, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    /// The bridge's version, for the bridge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sw_version: Option<String>,
    /// The bridge the device is heard through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_device: Option<String>,
}
