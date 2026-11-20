# Configuration reference

<!-- Generated from the configuration types by crates/bluetooth-bridge/tests/config_reference.rs. Do not edit by hand. -->

Every key the configuration file accepts. Unknown keys are an error, so a typo stops the bridge at startup instead of being ignored. This page is generated from the configuration types; a [JSON Schema](config.schema.json) generated from the same types lets editors with TOML schema support (for example Taplo or Even Better TOML) complete and check the file.

## `[adapter]`

The controller.

This table is required.

| Key | Type | Default | Description |
|---|---|---|---|
| `transport` | string | required | `hci0`, `serial:/dev/ttyAMA0:115200`, or `tcp:host:port`. |
| `name` | string | `"bluetooth-bridge"` | The GAP device name. |
| `appearance` | integer (0 to 65535) | `0` | The GAP appearance. |
| `io_capability` | `"display_only"`, `"display_yes_no"`, `"keyboard_only"`, `"no_input_no_output"`, `"keyboard_display"` | `"no_input_no_output"` | Input and output capabilities for pairing. `"display_only"`: Can show six digits. `"display_yes_no"`: Can show six digits and take yes or no. `"keyboard_only"`: Can take six digits. `"no_input_no_output"`: Neither. `"keyboard_display"`: Can show and take digits. |
| `passkey` | integer (from 0) | unset | A fixed passkey to show and type when pairing needs one (six digits). |
| `bonding` | boolean | `true` | Bond when pairing. |
| `mitm` | boolean | `false` | Require MITM protection. |
| `secure_connections_only` | boolean | `false` | Refuse legacy pairing. |
| `random_address` | boolean | `false` | Use a static random address even when the controller has a public one. |

## `[mqtt]`

The broker.

| Key | Type | Default | Description |
|---|---|---|---|
| `host` | string | `"localhost"` | Host name. |
| `port` | integer (0 to 65535) | `1883` | Port. |
| `username` | string | unset | User name. |
| `password_file` | string | unset | A file holding the password (so it is not in this file). |
| `client_id` | string | `"bluetooth-bridge"` | Client id. |
| `base_topic` | string | `"bluetooth"` | Every topic starts with this. |
| `keepalive` | integer (from 0) | `30` | Keep-alive, seconds. |

## `[scan]`

Scanning. (Unknown keys cannot be refused here: serde does not allow that with a flattened section.)

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Scan from start. |
| `active` | boolean | `false` | Send scan requests to get scan responses. |
| `interval_ms` | integer (from 0) | `100` | Scan interval, ms (2.5 to 10240). |
| `window_ms` | integer (from 0) | `100` | Scan window, ms (no more than the interval). |
| `coded` | boolean | `true` | Scan on the coded PHY too (long range), when the controller can. |
| `filter_accept_list` | boolean | `false` | Only devices on the filter accept list. |
| `dedup` | `"off"` or `"changes"` or `{ interval_ms = integer (from 0) }` | `{ interval_ms = 10000 }` | Duplicate filtering. Report every advertisement received. Report a device again only when its data changes. Report when its data changes, and at least every this many milliseconds while it is heard (so presence and RSSI stay current). |
| `allow` | array of string | `[]` | Publish only devices whose address starts with one of these (`BC:57:29`, say); empty publishes everything. |
| `min_rssi` | integer (-128 to 127) | `-127` | Ignore weaker signals, dBm. |
| `publish_reports` | boolean | `true` | Publish every report on `<base>/scan/<address>`. |

## `[homeassistant]`

Home Assistant discovery.

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Publish discovery for devices with decoded readings. |
| `discovery_prefix` | string | `"homeassistant"` | The discovery prefix. |
| `status_topic` | string | `"homeassistant/status"` | Home Assistant's birth topic; discovery is sent again when it comes online. |

## `[data]`

Storage.

| Key | Type | Default | Description |
|---|---|---|---|
| `dir` | string | `"/var/lib/bluetooth-bridge"` | The data directory. |

## `[[bthome_keys]]`

A device's key.

A list: repeat the `[[bthome_keys]]` table once per entry.

| Key | Type | Default | Description |
|---|---|---|---|
| `address` | string | required | The device's address. |
| `key` | string | required | The 16-byte key, hex. |

## `[[kkm_passwords]]`

A device's password.

A list: repeat the `[[kkm_passwords]]` table once per entry.

| Key | Type | Default | Description |
|---|---|---|---|
| `address` | string | required | The device's address. |
| `password` | string | required | The password. |

## `[[irks]]`

A known IRK.

A list: repeat the `[[irks]]` table once per entry.

| Key | Type | Default | Description |
|---|---|---|---|
| `address` | string | required | The identity address the device's private addresses stand for. |
| `irk` | string | required | The IRK, hex, most significant byte first. |
| `label` | string | unset | A label. |

## `[[gatt_services]]`

A service to add.

A list: repeat the `[[gatt_services]]` table once per entry.

| Key | Type | Default | Description |
|---|---|---|---|
| `uuid` | string | required | Its UUID. |
| `primary` | boolean | `true` | Primary (the default) or secondary. |

## `[[gatt_services.characteristics]]`

A characteristic to add.

A list: repeat the `[[gatt_services.characteristics]]` table once per entry.

| Key | Type | Default | Description |
|---|---|---|---|
| `uuid` | string | required | Its UUID. |
| `properties` | array of string | required | Its properties, by name: `read`, `write`, `write_without_response`, `notify`, `indicate`, `broadcast`. |
| `read` | `"never"`, `"open"`, `"encrypted"`, `"authenticated"`, `"secure_connections"` | `"open"` | Read access. `"never"`: Nobody. `"open"`: Anyone connected. `"encrypted"`: An encrypted link. `"authenticated"`: An encrypted link with an authenticated (MITM-protected) key. `"secure_connections"`: Authenticated LE Secure Connections with a 128-bit key. |
| `write` | `"never"`, `"open"`, `"encrypted"`, `"authenticated"`, `"secure_connections"` | `"open"` | Write access. `"never"`: Nobody. `"open"`: Anyone connected. `"encrypted"`: An encrypted link. `"authenticated"`: An encrypted link with an authenticated (MITM-protected) key. `"secure_connections"`: Authenticated LE Secure Connections with a 128-bit key. |
| `value` | string | `""` | The initial value. |
| `max_len` | integer (from 0) | `512` | The longest value a client may write (at most 512). |
| `description` | string | unset | A Characteristic User Description. |

## `[[gatt_services.characteristics.descriptors]]`

A descriptor to add.

A list: repeat the `[[gatt_services.characteristics.descriptors]]` table once per entry.

| Key | Type | Default | Description |
|---|---|---|---|
| `uuid` | string | required | Its UUID. |
| `read` | `"never"`, `"open"`, `"encrypted"`, `"authenticated"`, `"secure_connections"` | `"open"` | Read access. `"never"`: Nobody. `"open"`: Anyone connected. `"encrypted"`: An encrypted link. `"authenticated"`: An encrypted link with an authenticated (MITM-protected) key. `"secure_connections"`: Authenticated LE Secure Connections with a 128-bit key. |
| `write` | `"never"`, `"open"`, `"encrypted"`, `"authenticated"`, `"secure_connections"` | `"never"` | Write access. `"never"`: Nobody. `"open"`: Anyone connected. `"encrypted"`: An encrypted link. `"authenticated"`: An encrypted link with an authenticated (MITM-protected) key. `"secure_connections"`: Authenticated LE Secure Connections with a 128-bit key. |
| `value` | string | `""` | The value. |

## `[[advertising]]`

An advertising set.

A list: repeat the `[[advertising]]` table once per entry.

| Key | Type | Default | Description |
|---|---|---|---|
| `data` | string | `""` | Advertising data, hex (AD structures). |
| `scan_response` | string | `""` | Scan response, hex. |

## `[advertising.params]`

How a set advertises.

| Key | Type | Default | Description |
|---|---|---|---|
| `connectable` | boolean | `false` | Accept connections. |
| `scannable` | boolean | `false` | Answer scan requests with the scan response. |
| `legacy` | boolean | unset | Use legacy PDUs (seen by every scanner, 31 octets of data). `None` chooses: legacy when the data fits and nothing needs Bluetooth 5. |
| `directed` | string | unset | Advertise directed at one device. |
| `high_duty` | boolean | `false` | High duty cycle directed advertising (lasts 1.28 s at most). |
| `anonymous` | boolean | `false` | Omit our address (extended, non-connectable only). |
| `include_tx_power` | boolean | `false` | Put the TX power in the extended header. |
| `interval_min_ms` | integer (from 0) | `100` | Minimum interval, ms (20 or more). |
| `interval_max_ms` | integer (from 0) | `150` | Maximum interval, ms. |
| `primary_phy` | `"le1m"`, `"le2m"`, `"le_coded"` | `"le1m"` | Primary PHY: `le1m`, or `le_coded` for long range. `"le1m"`: LE 1M. `"le2m"`: LE 2M. `"le_coded"`: LE Coded (long range). |
| `secondary_phy` | `"le1m"`, `"le2m"`, `"le_coded"` | `"le1m"` | Secondary PHY (extended). `"le1m"`: LE 1M. `"le2m"`: LE 2M. `"le_coded"`: LE Coded (long range). |
| `tx_power` | integer (-128 to 127) | unset | TX power to ask for, dBm; `None` lets the controller choose. |
| `sid` | integer (0 to 255) | `0` | Advertising set id (0 to 15), as scanners see it. |
| `duration_ms` | integer (from 0) | unset | Stop after this long, ms. |
| `max_events` | integer (0 to 255) | unset | Stop after this many events (extended). |
| `filter_accept_list` | boolean | `false` | Only answer scan and connection requests from the filter accept list. |
| `scan_request_notifications` | boolean | `false` | Report scan requests as [`crate::HostEvent::ScanRequest`]. |
