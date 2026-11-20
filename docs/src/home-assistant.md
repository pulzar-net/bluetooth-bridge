# Home Assistant

bluetooth-bridge works with Home Assistant through its
[MQTT integration](https://www.home-assistant.io/integrations/mqtt/) and
MQTT discovery. There is no custom integration to install, and it does not
use Home Assistant's own Bluetooth integration: the bridge can run anywhere
on the network, as long as it is in radio range of the sensors.

## Setup

1. Run an MQTT broker, such as the
   [Mosquitto add-on](https://github.com/home-assistant/addons/tree/master/mosquitto).
2. Add the MQTT integration in Home Assistant (**Settings > Devices &
   services > Add integration > MQTT**) and point it at the broker.
3. Point bluetooth-bridge at the same broker and start it.

Sensors appear as they are heard.

## What is created

Each device with decoded readings becomes one Home Assistant device named
after its advertised name (or its address), with one `sensor` per reading
and a signal strength sensor (a diagnostic entity, disabled by default). Device classes follow the reading:
temperature, humidity, moisture, battery, voltage, pressure, illuminance,
VOC, energy, power, current, weight, distance, speed, volume, water, gas,
duration, signal strength, conductivity and precipitation. Binary readings
from BTHome (motion, door, and similar) become `binary_sensor`s.

The bridge itself is a device too, with a connectivity `binary_sensor` that
follows `bluetooth/bridge/state`; sensor entities use the same topic for
availability.

Discovery topics have the form
`homeassistant/sensor/bluetooth_<address>/<reading>/config`, for example
`homeassistant/sensor/bluetooth_f12233445566/temperature/config`.

## Topics

| Setting | Default | What |
|---|---|---|
| `homeassistant.discovery_prefix` | `homeassistant` | where discovery messages go |
| `homeassistant.status_topic` | `homeassistant/status` | Home Assistant's birth message; discovery is sent again when it says `online` |
| `homeassistant.enabled` | `true` | set `false` to publish no discovery |

## Several bridges

Give each bridge its own `mqtt.base_topic` and `mqtt.client_id`. Each
bridge is then a Home Assistant device of its own (`bluetooth_bridge` for
the default base topic, `bluetooth_bridge_<base topic>` for others), and
its sensors point at it. A sensor is identified by its address, not by the
bridge, so a sensor that two bridges hear is one Home Assistant device,
updated by whichever bridge heard it last. (In 0.1.0 the bridge's own
device id was fixed, so two bridges also shared that device.)
