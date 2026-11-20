"""A scripted Bluetooth peer for bluetooth-bridge's end-to-end tests.

Google's Bumble provides two virtual controllers on one simulated radio
link: the device under test (DUT) gets one over HCI on a TCP socket, H4
framed, exactly as it would get a real controller; the other is driven here
by a Bumble host as the scripted peer.

    python peer.py SCENARIO PORT [ARGS_JSON]

Events go to stdout as JSON lines ({"event": ...}); the test reads them.
Commands come on stdin as JSON lines, when a scenario needs a step from the
test. Exit status 0 means the scenario's own checks passed.
"""

import asyncio
import json
import logging
import sys

from bumble import gatt, l2cap
from bumble.controller import Controller
from bumble.core import AdvertisingData, UUID
from bumble.device import (
    AdvertisingEventProperties,
    AdvertisingParameters,
    Device,
    Peer,
    PeriodicAdvertisingParameters,
)
from bumble.hci import Address, OwnAddressType
from bumble.host import Host
from bumble.keys import MemoryKeyStore
from bumble.link import LocalLink
from bumble.pairing import PairingConfig, PairingDelegate
from bumble.smp import OobContext, OobLegacyContext
from bumble.transport import open_transport
from bumble.transport.common import AsyncPipeSink

PEER_ADDRESS = "F1:22:33:44:55:66"
DUT_PUBLIC = "D0:11:22:33:44:55"
SERVICE = UUID("6e400001-b5a3-f393-e0a9-e50e24dcca9e")
CHAR_LONG = UUID("6e400002-b5a3-f393-e0a9-e50e24dcca9e")
CHAR_WRITE = UUID("6e400003-b5a3-f393-e0a9-e50e24dcca9e")
CHAR_NOTIFY = UUID("6e400004-b5a3-f393-e0a9-e50e24dcca9e")
LONG_VALUE = bytes(range(256)) + bytes(range(44))  # 300 octets
PASSKEY = 123456


def emit(event, **kw):
    print(json.dumps({"event": event, **kw}), flush=True)


# asyncio keeps only weak references to tasks: hold them here.
TASKS = set()


def spawn(coro):
    task = asyncio.create_task(coro)
    TASKS.add(task)
    task.add_done_callback(TASKS.discard)
    return task


class Inbox:
    """Commands from the test, one JSON object per stdin line."""

    def __init__(self):
        self.queue = asyncio.Queue()

    async def start(self):
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(reader), sys.stdin
        )

        async def pump():
            while line := await reader.readline():
                await self.queue.put(json.loads(line))
            await self.queue.put({"op": "eof"})

        spawn(pump())

    async def get(self, op=None):
        while True:
            msg = await self.queue.get()
            if op is None or msg.get("op") in (op, "eof"):
                return msg


def ad(*fields):
    return bytes(AdvertisingData(list(fields)))


class Delegate(PairingDelegate):
    """Fixed answers: the passkey shown and typed, numbers always confirmed."""

    def __init__(self, io, **kw):
        super().__init__(io_capability=io, **kw)

    async def accept(self):
        return True

    async def confirm(self, auto=False):
        return True

    async def compare_numbers(self, number, digits):
        emit("compare", number=number)
        return True

    async def get_number(self):
        return PASSKEY

    async def generate_passkey(self):
        return PASSKEY

    async def display_number(self, number, digits):
        emit("display", number=number)


IO = {
    "no_input_no_output": PairingDelegate.NO_OUTPUT_NO_INPUT,
    "keyboard_only": PairingDelegate.KEYBOARD_INPUT_ONLY,
    "display_only": PairingDelegate.DISPLAY_OUTPUT_ONLY,
    "display_yes_no": PairingDelegate.DISPLAY_OUTPUT_AND_YES_NO_INPUT,
    "keyboard_display": PairingDelegate.DISPLAY_OUTPUT_AND_KEYBOARD_INPUT,
}


def pairing_config(device, args):
    oob = None
    if args.get("oob") == "sc":
        ctx = OobContext()
        shared = ctx.share()
        emit("oob", r=shared.r.hex(), c=shared.c.hex())
        oob = PairingConfig.OobConfig(our_context=ctx, peer_data=None, legacy_context=None)
    elif args.get("oob") == "legacy":
        tk = bytes.fromhex(args["tk"])
        oob = PairingConfig.OobConfig(
            our_context=None, peer_data=None, legacy_context=OobLegacyContext(tk=tk)
        )
    config = PairingConfig(
        sc=args.get("sc", True),
        mitm=args.get("mitm", False),
        bonding=True,
        delegate=Delegate(IO[args.get("io", "no_input_no_output")]),
        oob=oob,
    )
    device.pairing_config_factory = lambda connection: config


def gatt_server(device):
    """A service with a long readable value, a writable value and a
    notifying/indicating one."""

    def on_write(connection, value):
        emit("written", value=value.hex())

    notify = gatt.Characteristic(
        CHAR_NOTIFY,
        gatt.Characteristic.Properties.NOTIFY | gatt.Characteristic.Properties.INDICATE
        | gatt.Characteristic.Properties.READ,
        gatt.Characteristic.READABLE,
        b"\x00",
    )
    service = gatt.Service(
        SERVICE,
        [
            gatt.Characteristic(
                CHAR_LONG,
                gatt.Characteristic.Properties.READ,
                gatt.Characteristic.READABLE,
                LONG_VALUE,
            ),
            gatt.Characteristic(
                CHAR_WRITE,
                gatt.Characteristic.Properties.WRITE
                | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE
                | gatt.Characteristic.Properties.READ,
                gatt.Characteristic.READABLE | gatt.Characteristic.WRITEABLE,
                gatt.CharacteristicValue(write=on_write, read=lambda c: b"w"),
            ),
            notify,
        ],
    )
    device.add_service(service)
    return notify


async def wait_connection(device):
    fut = asyncio.get_running_loop().create_future()
    device.once("connection", fut.set_result)
    return await fut


# ----------------------------------------------------------------- scenarios


async def scan_legacy(device, args, inbox):
    """Legacy connectable advertising with a scan response carrying BTHome."""
    await device.start_advertising(
        advertising_data=ad(
            (AdvertisingData.FLAGS, bytes([0x06])),
            (AdvertisingData.COMPLETE_LOCAL_NAME, b"bumble-peer"),
            (AdvertisingData.MANUFACTURER_SPECIFIC_DATA, bytes([0xFF, 0xFF]) + b"hello"),
            (AdvertisingData.SERVICE_DATA_16_BIT_UUID, bytes.fromhex("d2fc4002ca0903bf13")),
        ),
        scan_response_data=ad((AdvertisingData.TX_POWER_LEVEL, bytes([0xF4]))),
        advertising_interval_min=20,
        advertising_interval_max=20,
    )
    emit("advertising", address=str(device.random_address))
    await inbox.get("stop")


async def scan_extended(device, args, inbox):
    """A non-connectable extended set with 200 octets of data, SID 3."""
    data = ad(
        (AdvertisingData.COMPLETE_LOCAL_NAME, b"bumble-extended"),
        (AdvertisingData.MANUFACTURER_SPECIFIC_DATA, bytes([0xFF, 0xFF]) + bytes(range(180))),
    )
    await device.create_advertising_set(
        advertising_parameters=AdvertisingParameters(
            advertising_event_properties=AdvertisingEventProperties(
                is_connectable=False, is_scannable=False, is_legacy=False
            ),
            primary_advertising_interval_min=20,
            primary_advertising_interval_max=20,
            advertising_sid=3,
        ),
        advertising_data=data,
    )
    emit("advertising", address=str(device.random_address), length=len(data))
    await inbox.get("stop")


async def periodic(device, args, inbox):
    """An extended set with a periodic train."""
    await device.create_advertising_set(
        advertising_parameters=AdvertisingParameters(
            advertising_event_properties=AdvertisingEventProperties(
                is_connectable=False, is_scannable=False, is_legacy=False
            ),
            primary_advertising_interval_min=20,
            primary_advertising_interval_max=20,
            advertising_sid=7,
        ),
        advertising_data=ad((AdvertisingData.COMPLETE_LOCAL_NAME, b"bumble-periodic")),
        periodic_advertising_parameters=PeriodicAdvertisingParameters(
            periodic_advertising_interval_min=20, periodic_advertising_interval_max=20
        ),
        periodic_advertising_data=ad(
            (AdvertisingData.MANUFACTURER_SPECIFIC_DATA, bytes([0xFF, 0xFF]) + b"periodic")
        ),
    )
    emit("advertising", address=str(device.random_address))
    await inbox.get("stop")


async def observe(device, args, inbox):
    """Scan and report what the DUT advertises."""
    seen = {}
    target = (await inbox.get("target"))["address"]

    def on_adv(a):
        if str(a.address).split("/")[0] != target:
            return
        key = (str(a.address), a.sid, a.is_scan_response, a.data_bytes)
        if key in seen:
            return
        seen[key] = True
        emit(
            "advertisement",
            address=str(a.address),
            data=a.data_bytes.hex(),
            legacy=a.is_legacy,
            sid=a.sid,
            connectable=a.is_connectable,
            scan_response=a.is_scan_response,
        )

    device.on("advertisement", on_adv)
    await device.start_scanning(legacy=False, active=True, filter_duplicates=False)
    emit("scanning")
    await inbox.get("stop")


async def peripheral(device, args, inbox):
    """A connectable peripheral with a GATT server, for the DUT as central."""
    notify = gatt_server(device)
    if args.get("pairing"):
        pairing_config(device, args["pairing"])

    async def on_subscription(connection, characteristic, notify_enabled, indicate_enabled):
        emit("subscribed", notify=notify_enabled, indicate=indicate_enabled)
        if notify_enabled:
            await device.notify_subscribers(notify, b"notified")
        if indicate_enabled:
            await device.indicate_subscribers(notify, b"indicated")
            emit("indication_confirmed")

    device.on(
        "characteristic_subscription",
        lambda c, ch, n, i: spawn(on_subscription(c, ch, n, i)),
    )

    def on_connection(connection):
        emit("connected", handle=connection.handle, peer=str(connection.peer_address))
        connection.on("pairing", lambda keys: emit(
            "paired",
            irk_present=keys.irk is not None,
            ltk_present=(keys.ltk is not None) or (keys.ltk_central is not None) or (keys.ltk_peripheral is not None),
        ))
        connection.on("pairing_failure", lambda reason: emit("pairing_failed", reason=int(reason)))
        connection.on("disconnection", lambda reason: emit("disconnected", reason=int(reason)))
        connection.on("connection_encryption_change", lambda: emit("encryption", encrypted=connection.is_encrypted))
        connection.on("connection_parameters_update", lambda: emit(
            "params", interval=connection.parameters.connection_interval))

    device.on("connection", on_connection)
    await device.start_advertising(
        advertising_data=ad(
            (AdvertisingData.FLAGS, bytes([0x06])),
            (AdvertisingData.COMPLETE_LOCAL_NAME, b"bumble-gatt"),
        ),
        advertising_interval_min=20,
        advertising_interval_max=20,
        auto_restart=True,
    )
    emit("advertising", address=str(device.random_address), irk=device.irk.hex())
    if args.get("l2cap"):
        def on_channel(channel):
            emit("channel", mtu=channel.peer_mtu)

            def on_sdu(sdu):
                emit("sdu", length=len(sdu))
                channel.write(sdu[::-1])

            channel.sink = on_sdu

        device.create_l2cap_server(
            spec=l2cap.LeCreditBasedChannelSpec(psm=0x0081, mtu=1024, mps=100, max_credits=8),
            handler=on_channel,
        )
    while True:
        msg = await inbox.get()
        if msg.get("op") in ("stop", "eof"):
            return
        if msg.get("op") == "request_params":
            for c in device.connections.values():
                await c.update_parameters(30, 40, 0, 400, use_l2cap=True)


async def central(device, args, inbox):
    """Connect to the DUT as central, then run its GATT server and pair."""
    if args.get("pairing"):
        pairing_config(device, args["pairing"])
    target = Address((await inbox.get("target"))["address"])
    connection = await device.connect(target, timeout=10)
    emit("connected", handle=connection.handle)
    connection.on("disconnection", lambda reason: emit("disconnected", reason=int(reason)))
    steps = args.get("steps", [])
    if "pair" in steps:
        fut = asyncio.get_running_loop().create_future()
        connection.on("pairing", lambda keys: fut.set_result(keys))
        connection.on("pairing_failure", lambda r: fut.set_exception(Exception(f"pairing failed {r}")))
        await connection.pair()
        keys = await asyncio.wait_for(fut, 20)
        emit("paired", irk=keys.irk.value.hex() if keys.irk else None,
             encrypted=connection.is_encrypted)
    if "gatt" in steps:
        peer = Peer(connection)
        mtu = await peer.request_mtu(247)
        emit("mtu", mtu=mtu)
        await peer.discover_services()
        services = peer.get_services_by_uuid(UUID(args["service"]))
        service = services[0]
        await service.discover_characteristics()
        chars = {str(c.uuid).lower(): c for c in service.characteristics}
        value = await peer.read_value(chars[args["read"].lower()])
        emit("read", value=bytes(value).hex())
        write = chars[args["write"].lower()]
        await peer.write_value(write, b"from bumble", with_response=True)
        long = bytes(range(200))
        await peer.write_value(write, long, with_response=True)
        emit("wrote")
        notify = chars[args["notify"].lower()]
        got = asyncio.get_running_loop().create_future()
        await peer.subscribe(notify, lambda v: got.done() or got.set_result(bytes(v)))
        emit("subscribed")
        value = await asyncio.wait_for(got, 10)
        emit("notification", value=value.hex())
    if "l2cap" in steps:
        channel = await connection.create_l2cap_channel(
            spec=l2cap.LeCreditBasedChannelSpec(psm=0x0083, mtu=1024, mps=60, max_credits=4)
        )
        got = asyncio.get_running_loop().create_future()
        channel.sink = lambda sdu: got.done() or got.set_result(bytes(sdu))
        channel.write(bytes(range(256)) * 2)
        echo = await asyncio.wait_for(got, 10)
        emit("echo", length=len(echo), ok=echo == (bytes(range(256)) * 2)[::-1])
    await inbox.get("stop")


async def rpa(device, args, inbox):
    """Advertise from a resolvable private address made with a known IRK."""
    irk = bytes.fromhex(args["irk"])
    address = Address.generate_private_address(irk)
    await device.create_advertising_set(
        advertising_parameters=AdvertisingParameters(
            own_address_type=OwnAddressType.RANDOM,
            primary_advertising_interval_min=20,
            primary_advertising_interval_max=20,
        ),
        random_address=address,
        advertising_data=ad((AdvertisingData.COMPLETE_LOCAL_NAME, b"bumble-private")),
    )
    emit("advertising", address=str(address))
    await inbox.get("stop")


async def idle(device, args, inbox):
    """Nothing scripted: the controllers are for hosts under test (two, with port2)."""
    await inbox.get("stop")


SCENARIOS = {
    "idle": idle,
    "scan_legacy": scan_legacy,
    "scan_extended": scan_extended,
    "periodic": periodic,
    "observe": observe,
    "peripheral": peripheral,
    "central": central,
    "rpa": rpa,
}


async def main():
    scenario, port = sys.argv[1], int(sys.argv[2])
    args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    link = LocalLink()
    transport = await open_transport(f"tcp-server:127.0.0.1:{port}")
    Controller(
        "DUT",
        host_source=transport.source,
        host_sink=transport.sink,
        link=link,
        public_address=DUT_PUBLIC,
    )
    second = None
    if args.get("port2"):
        # A second host under test on the same simulated link.
        second = await open_transport(f"tcp-server:127.0.0.1:{args['port2']}")
        Controller(
            "DUT2",
            host_source=second.source,
            host_sink=second.sink,
            link=link,
            public_address="D0:11:22:33:44:66",
        )
    peer_controller = Controller("PEER", link=link, public_address="E0:22:33:44:55:66")
    device = Device(
        address=Address(PEER_ADDRESS),
        host=Host(peer_controller, AsyncPipeSink(peer_controller)),
    )
    device.keystore = MemoryKeyStore()
    # Bumble's default IRK is all zeros, which means "no IRK"; use a real one.
    device.irk = bytes.fromhex("8a7d0b1c2e3f40516273849506a7b8c9")
    await device.power_on()
    inbox = Inbox()
    await inbox.start()
    emit("ready", address=PEER_ADDRESS)
    try:
        await SCENARIOS[scenario](device, args, inbox)
    except Exception as e:  # report, then fail the run
        emit("error", message=f"{type(e).__name__}: {e}")
        raise
    emit("done")
    await transport.close()
    if second:
        await second.close()


if __name__ == "__main__":
    import os

    logging.basicConfig(level=os.environ.get("BUMBLE_LOG", "WARNING").upper(), stream=sys.stderr)
    asyncio.run(main())
