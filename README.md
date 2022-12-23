## powertagd

**WARNING: Use at your own risks. This is currently unfinished and unpolished.**

Solution to read electrical measurements sent by Schneider PowerTag sensors.
These devices communicate with ZigBee Green Power and require precise control
of the timings to work reliably.

A `Sonoff ZigBee Dongle-E` device with custom firmware is used as a gateway. The
firmware is based on the NCP-UART firmware provided by Silicon Labs, modified to
automatically send a special ACK reply which is specific to PowerTags.

Currently the firmware is tailored for `Sonoff ZigBee Dongle-E` devices, but can
work on any devices using a Silicon Labs EFR32MGxx chip by adapting the pinout
and rebuilding. Firmware sources can be provided on request.

The `powertagd` software runs on the host and communicates with the dongle via
USB/UART using the Silicon Labs `EZSP` protocol. It manages the ZigBee network,
the commissioning of PowerTags, and processes the readings received from PowerTags.
Each received measurement is simply printed to `stdout` in
[InfluxDB Line Protocol](https://docs.influxdata.com/influxdb/cloud/reference/syntax/line-protocol/)
format. The output is intended to be piped to another app to process the data as needed.


## Quickstart

1. Flash the firmware to the dongle. You can either use the built-in bootloader
and upload the `ncp-uart-hw-gp-multi-rail.gbl` file, or flash the
`ncp-uart-hw-gp-multi-rail.s37` file directly with a JTAG debugger.<br>
__Warning:__ Be prepared to hook a JTAG debugger to recover the dongle if anything goes wrong.<br>
Check out [Sonoff firmware flashing](https://sonoff.tech/wp-content/uploads/2022/11/SONOFF-Zigbee-3.0-USB-dongle-plus-firmware-flashing-.pdf)
to use the bootloader method, just replace the firmware with the one in this repo.

2. Build `powertagd` with `make`.

3. Connect the USB dongle and determine where it was mapped in `/dev`.<br>
On Linux it should be something like `/dev/ttyACM0`<br>
On macOS it should be something like `/dev/cu.usbmodemXXXXXXXX`

4. (Optional) Run a network scan and pick the "best" channel:
    ```
    $ powertagd -d /dev/xxx scan
    ...
    Starting energy scan...
    Energy scan result: channel 11: -64 dBm
    Energy scan result: channel 12: -43 dBm
    Energy scan result: channel 13: -45 dBm
    Energy scan result: channel 14: -78 dBm
    Energy scan result: channel 15: -87 dBm
    Energy scan result: channel 16: -87 dBm
    Energy scan result: channel 17: -87 dBm
    Energy scan result: channel 18: -88 dBm
    Energy scan result: channel 19: -87 dBm
    Energy scan result: channel 20: -88 dBm
    Energy scan result: channel 21: -83 dBm
    Energy scan result: channel 22: -59 dBm
    Energy scan result: channel 23: -58 dBm
    Energy scan result: channel 24: -78 dBm
    Energy scan result: channel 25: -89 dBm
    Energy scan result: channel 26: -88 dBm
    ```

5. Create a ZigBee network on your preferred channel:
    ```
    powertagd -d /dev/xxx create <channel>
    ```

Finally run `powertagd -d /dev/xxx` to start the network. All unpaired PowerTags
in radio range should be automatically commissioned.

## TODO

- Clean up code
- Finish MQTT support
- Improve firmware to be able to send write commands to PowerTags.
For example to configure the direction of current flow.
- Figure out the remaining unknown attributes (0x4000, 0x4013, ...) sent by PowerTags.

## FAQ
### How to pick the best channel ?
The best channel is the one with the highest value in scan results (beware that value are negative).

Given the following scan result
```
Energy scan result: channel 11: -72 dBm
Energy scan result: channel 12: -73 dBm
Energy scan result: channel 13: -36 dBm
Energy scan result: channel 14: -33 dBm
Energy scan result: channel 15: -37 dBm
Energy scan result: channel 16: -50 dBm
Energy scan result: channel 17: -40 dBm
Energy scan result: channel 18: -40 dBm
Energy scan result: channel 19: -49 dBm
Energy scan result: channel 20: -50 dBm
Energy scan result: channel 21: -76 dBm
Energy scan result: channel 22: -79 dBm
Energy scan result: channel 23: -80 dBm
Energy scan result: channel 24: -80 dBm
Energy scan result: channel 25: -72 dBm
Energy scan result: channel 26: -27 dBm
```

The best channel is 26 then 14, the worst is 22.