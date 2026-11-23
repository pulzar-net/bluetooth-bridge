//! The MQTT reference on the docs site is an AsyncAPI description generated
//! from the payload types in `bluetooth_bridge::api`, the types the bridge
//! publishes, so it cannot drift from the code. This test fails when the
//! committed description differs from what the types say; regenerate it with
//!
//! ```sh
//! UPDATE_DOCS=1 cargo test -p bluetooth-bridge --features unstable-asyncapi-docs --test asyncapi
//! ```
//!
//! Topics are written with the default base topic (`bluetooth`) and discovery
//! prefix (`homeassistant`); the description says how to change them.

#![allow(clippy::duplicated_attributes)] // operations share channels by design
#![recursion_limit = "512"] // one attribute per channel and operation

use std::path::PathBuf;

use asyncapi_rust::AsyncApi;
use bluetooth_bridge::api::*;

const SPEC: &str = "docs/public/asyncapi.json";

/// The bridge's MQTT API.
#[derive(AsyncApi)]
#[asyncapi(
    title = "bluetooth-bridge MQTT API",
    version = "0.0.0",
    description = "Everything bluetooth-bridge publishes and accepts on MQTT.\n\nTopics here use the default base topic, `bluetooth` (`mqtt.base_topic` in the configuration), and Home Assistant's default discovery prefix, `homeassistant` (`homeassistant.discovery_prefix`). `{address}` is a device's address as twelve upper-case hex digits, most significant first (`BC5729000001`).\n\nThe bridge subscribes at QoS 1. It publishes its availability, its info and its own Home Assistant device at QoS 1, and everything that follows the radio (advertisements, readings, events, responses) at QoS 0, so a slow broker never stalls the scan. Payloads are JSON unless a message says otherwise; byte strings in them are lower-case hex. Requests go to `bluetooth/bridge/request/<name>`; the answer comes on `bluetooth/bridge/response/<name>`, echoing the request's `transaction` so a client can match the two. Keys never appear on MQTT."
)]
#[asyncapi_server(
    name = "broker",
    host = "localhost:1883",
    protocol = "mqtt",
    description = "Your MQTT broker: `mqtt.host` and `mqtt.port` in the configuration. The bridge connects with a clean session, its `mqtt.client_id`, and `bluetooth/bridge/state` set to offline as its last will.",
    mqtt(
        client_id = "bluetooth-bridge",
        clean_session = true,
        keep_alive = 30,
        last_will(
            topic = "bluetooth/bridge/state",
            qos = 1,
            message = "{\"state\":\"offline\"}",
            retain = true
        )
    )
)]
// The bridge, its events and the mesh's.
#[asyncapi_channel(
    name = "bridgeState",
    address = "bluetooth/bridge/state",
    description = "The bridge's availability, retained. `offline` is also the bridge's last will."
)]
#[asyncapi_channel(
    name = "bridgeInfo",
    address = "bluetooth/bridge/info",
    description = "The bridge and its controller, retained."
)]
#[asyncapi_channel(
    name = "bridgeEvent",
    address = "bluetooth/bridge/event",
    description = "Connections, pairing, notifications, writes to the bridge's GATT server and periodic advertising reports, as they happen. `type` names the event."
)]
#[asyncapi_channel(
    name = "meshEvent",
    address = "bluetooth/mesh/event",
    description = "Unprovisioned devices heard and access messages to the bridge. Only with `mesh.enabled`. `type` names the event."
)]
// Devices.
#[asyncapi_channel(
    name = "scanReport",
    address = "bluetooth/scan/{address}",
    description = "Every advertisement after duplicate filtering, parsed, with any beacon or sensor frames decoded. Only with `scan.publish_reports`.",
    parameter(
        name = "address",
        description = "The device's address: twelve upper-case hex digits, most significant first; its identity when a stored IRK resolves a private address.",
        examples = ["BC5729000001", "A4C138000001"]
    )
)]
#[asyncapi_channel(
    name = "deviceState",
    address = "bluetooth/device/{address}",
    description = "A device's decoded readings, for devices whose advertisements carry any (BTHome, KKM, Ruuvi, Eddystone TLM). Home Assistant's entities read it.",
    parameter(
        name = "address",
        description = "The device's address: twelve upper-case hex digits, most significant first; its identity when a stored IRK resolves a private address.",
        examples = ["BC5729000001", "A4C138000001"]
    )
)]
// Requests and their responses.
#[asyncapi_channel(
    name = "infoRequest",
    address = "bluetooth/bridge/request/info",
    description = "The controller's address and capabilities."
)]
#[asyncapi_channel(
    name = "infoResponse",
    address = "bluetooth/bridge/response/info",
    description = "The answer to `info`."
)]
#[asyncapi_channel(
    name = "scanStartRequest",
    address = "bluetooth/bridge/request/scan/start",
    description = "Start scanning, or restart it with another configuration."
)]
#[asyncapi_channel(
    name = "scanStartResponse",
    address = "bluetooth/bridge/response/scan/start",
    description = "The answer to `scan/start`."
)]
#[asyncapi_channel(
    name = "scanStopRequest",
    address = "bluetooth/bridge/request/scan/stop",
    description = "Stop scanning."
)]
#[asyncapi_channel(
    name = "scanStopResponse",
    address = "bluetooth/bridge/response/scan/stop",
    description = "The answer to `scan/stop`."
)]
#[asyncapi_channel(
    name = "connectRequest",
    address = "bluetooth/bridge/request/connect",
    description = "Connect to a device as central."
)]
#[asyncapi_channel(
    name = "connectResponse",
    address = "bluetooth/bridge/response/connect",
    description = "The answer to `connect`."
)]
#[asyncapi_channel(
    name = "disconnectRequest",
    address = "bluetooth/bridge/request/disconnect",
    description = "Close a connection."
)]
#[asyncapi_channel(
    name = "disconnectResponse",
    address = "bluetooth/bridge/response/disconnect",
    description = "The answer to `disconnect`."
)]
#[asyncapi_channel(
    name = "connectionsRequest",
    address = "bluetooth/bridge/request/connections",
    description = "The open connections."
)]
#[asyncapi_channel(
    name = "connectionsResponse",
    address = "bluetooth/bridge/response/connections",
    description = "The answer to `connections`."
)]
#[asyncapi_channel(
    name = "connectionParamsRequest",
    address = "bluetooth/bridge/request/connection/params",
    description = "Ask for new connection parameters."
)]
#[asyncapi_channel(
    name = "connectionParamsResponse",
    address = "bluetooth/bridge/response/connection/params",
    description = "The answer to `connection/params`."
)]
#[asyncapi_channel(
    name = "connectionPhyRequest",
    address = "bluetooth/bridge/request/connection/phy",
    description = "Ask for other PHYs on a connection."
)]
#[asyncapi_channel(
    name = "connectionPhyResponse",
    address = "bluetooth/bridge/response/connection/phy",
    description = "The answer to `connection/phy`."
)]
#[asyncapi_channel(
    name = "connectionDataLengthRequest",
    address = "bluetooth/bridge/request/connection/data_length",
    description = "Set the largest packets the bridge sends on a connection."
)]
#[asyncapi_channel(
    name = "connectionDataLengthResponse",
    address = "bluetooth/bridge/response/connection/data_length",
    description = "The answer to `connection/data_length`."
)]
#[asyncapi_channel(
    name = "connectionRssiRequest",
    address = "bluetooth/bridge/request/connection/rssi",
    description = "Read a connection's signal strength."
)]
#[asyncapi_channel(
    name = "connectionRssiResponse",
    address = "bluetooth/bridge/response/connection/rssi",
    description = "The answer to `connection/rssi`."
)]
#[asyncapi_channel(
    name = "gattMtuRequest",
    address = "bluetooth/bridge/request/gatt/mtu",
    description = "Exchange the ATT MTU with a peer."
)]
#[asyncapi_channel(
    name = "gattMtuResponse",
    address = "bluetooth/bridge/response/gatt/mtu",
    description = "The answer to `gatt/mtu`."
)]
#[asyncapi_channel(
    name = "gattDiscoverRequest",
    address = "bluetooth/bridge/request/gatt/discover",
    description = "Discover a peer's services, characteristics and descriptors."
)]
#[asyncapi_channel(
    name = "gattDiscoverResponse",
    address = "bluetooth/bridge/response/gatt/discover",
    description = "The answer to `gatt/discover`."
)]
#[asyncapi_channel(
    name = "gattReadRequest",
    address = "bluetooth/bridge/request/gatt/read",
    description = "Read a peer's attribute."
)]
#[asyncapi_channel(
    name = "gattReadResponse",
    address = "bluetooth/bridge/response/gatt/read",
    description = "The answer to `gatt/read`."
)]
#[asyncapi_channel(
    name = "gattWriteRequest",
    address = "bluetooth/bridge/request/gatt/write",
    description = "Write a peer's attribute."
)]
#[asyncapi_channel(
    name = "gattWriteResponse",
    address = "bluetooth/bridge/response/gatt/write",
    description = "The answer to `gatt/write`."
)]
#[asyncapi_channel(
    name = "gattSubscribeRequest",
    address = "bluetooth/bridge/request/gatt/subscribe",
    description = "Turn a peer characteristic's notifications or indications on or off. They arrive as `notification` events."
)]
#[asyncapi_channel(
    name = "gattSubscribeResponse",
    address = "bluetooth/bridge/response/gatt/subscribe",
    description = "The answer to `gatt/subscribe`."
)]
#[asyncapi_channel(
    name = "pairRequest",
    address = "bluetooth/bridge/request/pair",
    description = "Pair with a connected peer."
)]
#[asyncapi_channel(
    name = "pairResponse",
    address = "bluetooth/bridge/response/pair",
    description = "The answer to `pair`."
)]
#[asyncapi_channel(
    name = "secureRequest",
    address = "bluetooth/bridge/request/secure",
    description = "Encrypt a link with a stored key, pairing when there is none."
)]
#[asyncapi_channel(
    name = "secureResponse",
    address = "bluetooth/bridge/response/secure",
    description = "The answer to `secure`."
)]
#[asyncapi_channel(
    name = "unpairRequest",
    address = "bluetooth/bridge/request/unpair",
    description = "Forget a bond."
)]
#[asyncapi_channel(
    name = "unpairResponse",
    address = "bluetooth/bridge/response/unpair",
    description = "The answer to `unpair`."
)]
#[asyncapi_channel(
    name = "bondsRequest",
    address = "bluetooth/bridge/request/bonds",
    description = "The stored bonds: who, and what kind of keys. Keys are never published."
)]
#[asyncapi_channel(
    name = "bondsResponse",
    address = "bluetooth/bridge/response/bonds",
    description = "The answer to `bonds`."
)]
#[asyncapi_channel(
    name = "advertiseStartRequest",
    address = "bluetooth/bridge/request/advertise/start",
    description = "Start an advertising set."
)]
#[asyncapi_channel(
    name = "advertiseStartResponse",
    address = "bluetooth/bridge/response/advertise/start",
    description = "The answer to `advertise/start`."
)]
#[asyncapi_channel(
    name = "advertiseDataRequest",
    address = "bluetooth/bridge/request/advertise/data",
    description = "Change a set's data while it advertises."
)]
#[asyncapi_channel(
    name = "advertiseDataResponse",
    address = "bluetooth/bridge/response/advertise/data",
    description = "The answer to `advertise/data`."
)]
#[asyncapi_channel(
    name = "advertiseStopRequest",
    address = "bluetooth/bridge/request/advertise/stop",
    description = "Stop an advertising set."
)]
#[asyncapi_channel(
    name = "advertiseStopResponse",
    address = "bluetooth/bridge/response/advertise/stop",
    description = "The answer to `advertise/stop`."
)]
#[asyncapi_channel(
    name = "periodicStartRequest",
    address = "bluetooth/bridge/request/periodic/start",
    description = "Start periodic advertising on an extended set."
)]
#[asyncapi_channel(
    name = "periodicStartResponse",
    address = "bluetooth/bridge/response/periodic/start",
    description = "The answer to `periodic/start`."
)]
#[asyncapi_channel(
    name = "periodicStopRequest",
    address = "bluetooth/bridge/request/periodic/stop",
    description = "Stop a set's periodic advertising."
)]
#[asyncapi_channel(
    name = "periodicStopResponse",
    address = "bluetooth/bridge/response/periodic/stop",
    description = "The answer to `periodic/stop`."
)]
#[asyncapi_channel(
    name = "periodicSyncRequest",
    address = "bluetooth/bridge/request/periodic/sync",
    description = "Follow another device's periodic advertising train. Its reports arrive as `periodic_report` events."
)]
#[asyncapi_channel(
    name = "periodicSyncResponse",
    address = "bluetooth/bridge/response/periodic/sync",
    description = "The answer to `periodic/sync`."
)]
#[asyncapi_channel(
    name = "periodicTerminateRequest",
    address = "bluetooth/bridge/request/periodic/terminate",
    description = "Stop following a periodic advertising train."
)]
#[asyncapi_channel(
    name = "periodicTerminateResponse",
    address = "bluetooth/bridge/response/periodic/terminate",
    description = "The answer to `periodic/terminate`."
)]
#[asyncapi_channel(
    name = "serverAddRequest",
    address = "bluetooth/bridge/request/server/add",
    description = "Add a service to the bridge's GATT server."
)]
#[asyncapi_channel(
    name = "serverAddResponse",
    address = "bluetooth/bridge/response/server/add",
    description = "The answer to `server/add`."
)]
#[asyncapi_channel(
    name = "serverSetRequest",
    address = "bluetooth/bridge/request/server/set",
    description = "Set a value in the bridge's GATT server, and optionally notify its subscribers."
)]
#[asyncapi_channel(
    name = "serverSetResponse",
    address = "bluetooth/bridge/response/server/set",
    description = "The answer to `server/set`."
)]
#[asyncapi_channel(
    name = "serverGetRequest",
    address = "bluetooth/bridge/request/server/get",
    description = "Read a value from the bridge's GATT server."
)]
#[asyncapi_channel(
    name = "serverGetResponse",
    address = "bluetooth/bridge/response/server/get",
    description = "The answer to `server/get`."
)]
#[asyncapi_channel(
    name = "meshNetworkRequest",
    address = "bluetooth/bridge/request/mesh/network",
    description = "The mesh network: the bridge's address, the IV index and the nodes it provisioned. Mesh requests need `mesh.enabled`."
)]
#[asyncapi_channel(
    name = "meshNetworkResponse",
    address = "bluetooth/bridge/response/mesh/network",
    description = "The answer to `mesh/network`."
)]
#[asyncapi_channel(
    name = "meshUnprovisionedRequest",
    address = "bluetooth/bridge/request/mesh/unprovisioned",
    description = "The unprovisioned devices whose beacons were heard, newest first."
)]
#[asyncapi_channel(
    name = "meshUnprovisionedResponse",
    address = "bluetooth/bridge/response/mesh/unprovisioned",
    description = "The answer to `mesh/unprovisioned`."
)]
#[asyncapi_channel(
    name = "meshProvisionRequest",
    address = "bluetooth/bridge/request/mesh/provision",
    description = "Provision a device into the network. Waits up to two minutes."
)]
#[asyncapi_channel(
    name = "meshProvisionResponse",
    address = "bluetooth/bridge/response/mesh/provision",
    description = "The answer to `mesh/provision`."
)]
#[asyncapi_channel(
    name = "meshConfigureRequest",
    address = "bluetooth/bridge/request/mesh/configure",
    description = "Give a node the application key, bind its models and read its Composition Data. Waits up to a minute."
)]
#[asyncapi_channel(
    name = "meshConfigureResponse",
    address = "bluetooth/bridge/response/mesh/configure",
    description = "The answer to `mesh/configure`."
)]
#[asyncapi_channel(
    name = "meshOnoffRequest",
    address = "bluetooth/bridge/request/mesh/onoff",
    description = "Switch a node's Generic OnOff server. Waits up to 30 seconds for its status."
)]
#[asyncapi_channel(
    name = "meshOnoffResponse",
    address = "bluetooth/bridge/response/mesh/onoff",
    description = "The answer to `mesh/onoff`."
)]
// Home Assistant.
#[asyncapi_channel(
    name = "homeAssistantDiscovery",
    address = "homeassistant/{component}/{node_id}/{object_id}/config",
    description = "Home Assistant MQTT discovery: one retained config per reading of a device, sent the first time the bridge hears the reading and again when Home Assistant comes online, and one for the bridge's own connection state. Only with `homeassistant.enabled`.",
    parameter(
        name = "component",
        description = "The entity type.",
        enum_values = ["sensor", "binary_sensor"]
    ),
    parameter(
        name = "node_id",
        description = "`bluetooth_` and the device's address in lower case, or the bridge's id: `bluetooth_bridge` for the default base topic.",
        examples = ["bluetooth_a4c138000001", "bluetooth_bridge"]
    ),
    parameter(
        name = "object_id",
        description = "The reading: `temperature`, `battery`, `rssi` and so on, or `connection_state` for the bridge.",
        examples = ["temperature", "connection_state"]
    )
)]
#[asyncapi_channel(
    name = "homeAssistantStatus",
    address = "homeassistant/status",
    description = "Home Assistant's birth and last will (`homeassistant.status_topic`). When it says `online`, the bridge publishes discovery again."
)]
// What the bridge publishes.
#[asyncapi_operation(name = "publishBridgeState", summary = "The bridge is online or offline", action = "send", channel = "bridgeState", description = "Published `online` on connecting and `offline` on stopping.", messages = [BridgeState], mqtt(qos = 1, retain = true))]
#[asyncapi_operation(name = "publishBridgeInfo", summary = "The bridge's version and its controller", action = "send", channel = "bridgeInfo", description = "Published on connecting.", messages = [BridgeInfo], mqtt(qos = 1, retain = true))]
#[asyncapi_operation(name = "publishBridgeEvent", summary = "Something happened on the radio", action = "send", channel = "bridgeEvent", description = "Published as each event happens.", messages = [BridgeEvent], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "publishMeshEvent", summary = "Something happened in the mesh", action = "send", channel = "meshEvent", description = "Published as each event happens.", messages = [MeshEvent], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "publishScanReport", summary = "An advertisement, parsed and decoded", action = "send", channel = "scanReport", description = "Published for each advertisement that passes `scan.min_rssi` and `scan.allow`.", messages = [ScanReport], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "publishDeviceState", summary = "A device's readings", action = "send", channel = "deviceState", description = "Published after each advertisement with readings.", messages = [DeviceState], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "publishDiscovery", summary = "A Home Assistant entity", action = "send", channel = "homeAssistantDiscovery", description = "Published per entity: the bridge's own at QoS 1, a device's at QoS 0.", messages = [DiscoveryConfig], mqtt(qos = 0, retain = true))]
// What the bridge receives.
#[asyncapi_operation(name = "receiveHomeAssistantStatus", summary = "Home Assistant started or stopped", action = "receive", channel = "homeAssistantStatus", description = "Read only with `homeassistant.enabled`.", messages = [HomeAssistantStatus], mqtt(qos = 1))]
#[asyncapi_operation(name = "receiveInfo", summary = "Ask for the controller", action = "receive", channel = "infoRequest", description = "Answered on `bluetooth/bridge/response/info`.", messages = [EmptyRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendInfo", summary = "The controller", action = "send", channel = "infoResponse", description = "The result, or the error when the request could not be read or done.", messages = [InfoResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveScanStart", summary = "Start scanning", action = "receive", channel = "scanStartRequest", description = "Answered on `bluetooth/bridge/response/scan/start`.", messages = [ScanStartRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendScanStart", summary = "Scanning started", action = "send", channel = "scanStartResponse", description = "The result, or the error when the request could not be read or done.", messages = [DoneResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveScanStop", summary = "Stop scanning", action = "receive", channel = "scanStopRequest", description = "Answered on `bluetooth/bridge/response/scan/stop`.", messages = [EmptyRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendScanStop", summary = "Scanning stopped", action = "send", channel = "scanStopResponse", description = "The result, or the error when the request could not be read or done.", messages = [DoneResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveConnect", summary = "Connect to a device", action = "receive", channel = "connectRequest", description = "Answered on `bluetooth/bridge/response/connect`.", messages = [ConnectRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendConnect", summary = "The device is connected", action = "send", channel = "connectResponse", description = "The result, or the error when the request could not be read or done.", messages = [ConnectResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveDisconnect", summary = "Close a connection", action = "receive", channel = "disconnectRequest", description = "Answered on `bluetooth/bridge/response/disconnect`.", messages = [HandleRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendDisconnect", summary = "The connection is closed", action = "send", channel = "disconnectResponse", description = "The result, or the error when the request could not be read or done.", messages = [DoneResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveConnections", summary = "List the connections", action = "receive", channel = "connectionsRequest", description = "Answered on `bluetooth/bridge/response/connections`.", messages = [EmptyRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendConnections", summary = "The open connections", action = "send", channel = "connectionsResponse", description = "The result, or the error when the request could not be read or done.", messages = [ConnectionsResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveConnectionParams", summary = "Change a connection's parameters", action = "receive", channel = "connectionParamsRequest", description = "Answered on `bluetooth/bridge/response/connection/params`.", messages = [ConnectionParamsRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendConnectionParams", summary = "The parameters now in use", action = "send", channel = "connectionParamsResponse", description = "The result, or the error when the request could not be read or done.", messages = [ConnectionParamsResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveConnectionPhy", summary = "Change a connection's PHYs", action = "receive", channel = "connectionPhyRequest", description = "Answered on `bluetooth/bridge/response/connection/phy`.", messages = [ConnectionPhyRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendConnectionPhy", summary = "The PHYs now in use", action = "send", channel = "connectionPhyResponse", description = "The result, or the error when the request could not be read or done.", messages = [ConnectionPhyResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveConnectionDataLength", summary = "Change a connection's data length", action = "receive", channel = "connectionDataLengthRequest", description = "Answered on `bluetooth/bridge/response/connection/data_length`.", messages = [ConnectionDataLengthRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendConnectionDataLength", summary = "The data length is asked for", action = "send", channel = "connectionDataLengthResponse", description = "The result, or the error when the request could not be read or done.", messages = [DoneResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveConnectionRssi", summary = "Read a connection's signal strength", action = "receive", channel = "connectionRssiRequest", description = "Answered on `bluetooth/bridge/response/connection/rssi`.", messages = [HandleRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendConnectionRssi", summary = "The connection's signal strength", action = "send", channel = "connectionRssiResponse", description = "The result, or the error when the request could not be read or done.", messages = [ConnectionRssiResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveGattMtu", summary = "Exchange the ATT MTU", action = "receive", channel = "gattMtuRequest", description = "Answered on `bluetooth/bridge/response/gatt/mtu`.", messages = [GattMtuRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendGattMtu", summary = "The ATT MTU now in use", action = "send", channel = "gattMtuResponse", description = "The result, or the error when the request could not be read or done.", messages = [GattMtuResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveGattDiscover", summary = "Discover a peer's GATT database", action = "receive", channel = "gattDiscoverRequest", description = "Answered on `bluetooth/bridge/response/gatt/discover`.", messages = [HandleRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendGattDiscover", summary = "The peer's services", action = "send", channel = "gattDiscoverResponse", description = "The result, or the error when the request could not be read or done.", messages = [GattDiscoverResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveGattRead", summary = "Read an attribute", action = "receive", channel = "gattReadRequest", description = "Answered on `bluetooth/bridge/response/gatt/read`.", messages = [GattReadRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendGattRead", summary = "The attribute's value", action = "send", channel = "gattReadResponse", description = "The result, or the error when the request could not be read or done.", messages = [GattReadResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveGattWrite", summary = "Write an attribute", action = "receive", channel = "gattWriteRequest", description = "Answered on `bluetooth/bridge/response/gatt/write`.", messages = [GattWriteRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendGattWrite", summary = "The attribute is written", action = "send", channel = "gattWriteResponse", description = "The result, or the error when the request could not be read or done.", messages = [DoneResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveGattSubscribe", summary = "Subscribe to a characteristic", action = "receive", channel = "gattSubscribeRequest", description = "Answered on `bluetooth/bridge/response/gatt/subscribe`.", messages = [GattSubscribeRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendGattSubscribe", summary = "The subscription is set", action = "send", channel = "gattSubscribeResponse", description = "The result, or the error when the request could not be read or done.", messages = [DoneResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receivePair", summary = "Pair with a peer", action = "receive", channel = "pairRequest", description = "Answered on `bluetooth/bridge/response/pair`.", messages = [HandleRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendPair", summary = "The link's security after pairing", action = "send", channel = "pairResponse", description = "The result, or the error when the request could not be read or done.", messages = [SecurityResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveSecure", summary = "Encrypt a link", action = "receive", channel = "secureRequest", description = "Answered on `bluetooth/bridge/response/secure`.", messages = [HandleRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendSecure", summary = "The link's security", action = "send", channel = "secureResponse", description = "The result, or the error when the request could not be read or done.", messages = [SecurityResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveUnpair", summary = "Forget a bond", action = "receive", channel = "unpairRequest", description = "Answered on `bluetooth/bridge/response/unpair`.", messages = [UnpairRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendUnpair", summary = "The bond is forgotten", action = "send", channel = "unpairResponse", description = "The result, or the error when the request could not be read or done.", messages = [UnpairResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveBonds", summary = "List the bonds", action = "receive", channel = "bondsRequest", description = "Answered on `bluetooth/bridge/response/bonds`.", messages = [EmptyRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendBonds", summary = "The stored bonds", action = "send", channel = "bondsResponse", description = "The result, or the error when the request could not be read or done.", messages = [BondsResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveAdvertiseStart", summary = "Start advertising", action = "receive", channel = "advertiseStartRequest", description = "Answered on `bluetooth/bridge/response/advertise/start`.", messages = [AdvertiseStartRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendAdvertiseStart", summary = "The advertising set started", action = "send", channel = "advertiseStartResponse", description = "The result, or the error when the request could not be read or done.", messages = [AdvertiseStartResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveAdvertiseData", summary = "Change a set's advertising data", action = "receive", channel = "advertiseDataRequest", description = "Answered on `bluetooth/bridge/response/advertise/data`.", messages = [AdvertiseDataRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendAdvertiseData", summary = "The set's data changed", action = "send", channel = "advertiseDataResponse", description = "The result, or the error when the request could not be read or done.", messages = [DoneResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveAdvertiseStop", summary = "Stop advertising", action = "receive", channel = "advertiseStopRequest", description = "Answered on `bluetooth/bridge/response/advertise/stop`.", messages = [SetRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendAdvertiseStop", summary = "The set stopped", action = "send", channel = "advertiseStopResponse", description = "The result, or the error when the request could not be read or done.", messages = [DoneResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receivePeriodicStart", summary = "Start periodic advertising", action = "receive", channel = "periodicStartRequest", description = "Answered on `bluetooth/bridge/response/periodic/start`.", messages = [PeriodicStartRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendPeriodicStart", summary = "Periodic advertising started", action = "send", channel = "periodicStartResponse", description = "The result, or the error when the request could not be read or done.", messages = [DoneResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receivePeriodicStop", summary = "Stop periodic advertising", action = "receive", channel = "periodicStopRequest", description = "Answered on `bluetooth/bridge/response/periodic/stop`.", messages = [SetRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendPeriodicStop", summary = "Periodic advertising stopped", action = "send", channel = "periodicStopResponse", description = "The result, or the error when the request could not be read or done.", messages = [DoneResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receivePeriodicSync", summary = "Follow a periodic advertising train", action = "receive", channel = "periodicSyncRequest", description = "Answered on `bluetooth/bridge/response/periodic/sync`.", messages = [PeriodicSyncRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendPeriodicSync", summary = "The train is followed", action = "send", channel = "periodicSyncResponse", description = "The result, or the error when the request could not be read or done.", messages = [PeriodicSyncResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receivePeriodicTerminate", summary = "Stop following a train", action = "receive", channel = "periodicTerminateRequest", description = "Answered on `bluetooth/bridge/response/periodic/terminate`.", messages = [PeriodicTerminateRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendPeriodicTerminate", summary = "The train is no longer followed", action = "send", channel = "periodicTerminateResponse", description = "The result, or the error when the request could not be read or done.", messages = [DoneResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveServerAdd", summary = "Add a GATT service", action = "receive", channel = "serverAddRequest", description = "Answered on `bluetooth/bridge/response/server/add`.", messages = [ServerAddRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendServerAdd", summary = "The service's handles", action = "send", channel = "serverAddResponse", description = "The result, or the error when the request could not be read or done.", messages = [ServerAddResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveServerSet", summary = "Set a characteristic's value", action = "receive", channel = "serverSetRequest", description = "Answered on `bluetooth/bridge/response/server/set`.", messages = [ServerSetRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendServerSet", summary = "The value is set", action = "send", channel = "serverSetResponse", description = "The result, or the error when the request could not be read or done.", messages = [ServerSetResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveServerGet", summary = "Read a characteristic's value", action = "receive", channel = "serverGetRequest", description = "Answered on `bluetooth/bridge/response/server/get`.", messages = [ServerGetRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendServerGet", summary = "The value", action = "send", channel = "serverGetResponse", description = "The result, or the error when the request could not be read or done.", messages = [ServerGetResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveMeshNetwork", summary = "Show the mesh network", action = "receive", channel = "meshNetworkRequest", description = "Answered on `bluetooth/bridge/response/mesh/network`.", messages = [EmptyRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendMeshNetwork", summary = "The mesh network", action = "send", channel = "meshNetworkResponse", description = "The result, or the error when the request could not be read or done.", messages = [MeshNetworkResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveMeshUnprovisioned", summary = "List unprovisioned devices", action = "receive", channel = "meshUnprovisionedRequest", description = "Answered on `bluetooth/bridge/response/mesh/unprovisioned`.", messages = [EmptyRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendMeshUnprovisioned", summary = "The unprovisioned devices heard", action = "send", channel = "meshUnprovisionedResponse", description = "The result, or the error when the request could not be read or done.", messages = [MeshUnprovisionedResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveMeshProvision", summary = "Provision a device", action = "receive", channel = "meshProvisionRequest", description = "Answered on `bluetooth/bridge/response/mesh/provision`.", messages = [MeshProvisionRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendMeshProvision", summary = "The device is a node", action = "send", channel = "meshProvisionResponse", description = "The result, or the error when the request could not be read or done.", messages = [MeshProvisionResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveMeshConfigure", summary = "Configure a node", action = "receive", channel = "meshConfigureRequest", description = "Answered on `bluetooth/bridge/response/mesh/configure`.", messages = [MeshConfigureRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendMeshConfigure", summary = "The node's composition", action = "send", channel = "meshConfigureResponse", description = "The result, or the error when the request could not be read or done.", messages = [MeshConfigureResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
#[asyncapi_operation(name = "receiveMeshOnoff", summary = "Switch a node on or off", action = "receive", channel = "meshOnoffRequest", description = "Answered on `bluetooth/bridge/response/mesh/onoff`.", messages = [MeshOnOffRequest], mqtt(qos = 1))]
#[asyncapi_operation(name = "sendMeshOnoff", summary = "The node's state", action = "send", channel = "meshOnoffResponse", description = "The result, or the error when the request could not be read or done.", messages = [MeshOnOffResponse, ErrorResponse], mqtt(qos = 0, retain = false))]
struct MqttApi;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn render() -> String {
    let mut spec = MqttApi::asyncapi_spec();
    // The description is versioned with the bridge.
    spec.info.version = env!("CARGO_PKG_VERSION").into();
    serde_json::to_string_pretty(&spec).unwrap() + "\n"
}

#[test]
fn asyncapi_description_is_current() {
    let json = render();
    let path = repo_root().join(SPEC);
    if std::env::var_os("UPDATE_DOCS").is_some() {
        std::fs::write(&path, &json).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == json,
        "{SPEC} is stale: regenerate it with \
         UPDATE_DOCS=1 cargo test -p bluetooth-bridge --features unstable-asyncapi-docs --test asyncapi"
    );
}
