## powertagd

Solution to read electrical measurements sent by Schneider PowerTag sensors.
These devices communicate with ZigBee Green Power and require precise control
of the timings to work reliably.

A `Sonoff ZigBee Dongle-E` device (not the -P model!) with custom firmware is
used as a gateway. The firmware is based on the NCP-UART firmware provided by
Silicon Labs, modified to automatically send a special ACK reply which is specific to PowerTags.

Currently the firmware is tailored for `Sonoff ZigBee Dongle-E` devices, but can
work on any devices using a Silicon Labs EFR32MGxx chip by adapting the pinout
and rebuilding. Firmware sources can be provided on request.

The `powertagd` command runs on the host and communicates with the dongle via
USB/UART using Silicon Labs `EZSP` protocol. It processes the readings received
from PowerTags. By default, each received measurement is simply printed to `stdout` in
[InfluxDB Line Protocol](https://docs.influxdata.com/influxdb/cloud/reference/syntax/line-protocol/)
format. This output is intended to be piped to another app to process the data as needed.

The `powertagctl` command is used to create the ZigBee network, commission
and configure the PowerTags.


## Quickstart

1. Flash the firmware to the dongle. You can either use the built-in bootloader
and upload the `ncp-uart-hw-gp-multi-rail.gbl` file, or flash the
`ncp-uart-hw-gp-multi-rail.s37` file directly with a JTAG debugger.<br>
__Warning:__ Be prepared to hook a JTAG debugger to recover the dongle if anything goes wrong.<br>
Check out [Sonoff firmware flashing](https://sonoff.tech/wp-content/uploads/2022/11/SONOFF-Zigbee-3.0-USB-dongle-plus-firmware-flashing-.pdf)
to use the bootloader method, just replace the firmware with the one in this repo.

2. Build `powertagd` and `powertagctl` by running `make` in the `src` directory.

3. Connect the USB dongle and determine where it was mapped in `/dev`.<br>
On Linux it should be something like `/dev/ttyACM0`<br>
On macOS it should be something like `/dev/cu.usbmodemXXXXXXXX`

4. (Optional) Run a network scan and choose a channel. The closer the dBm value is
    to 0, the stronger the signal. In the following example the best picks would
    be channel 12 or 13.
    ```
    $ powertagctl -d /dev/xxx scan
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
    powertagctl -d /dev/xxx create <channel>
    ```

6. Commission PowerTags:
    ```
    powertagctl -d /dev/xxx pair
    ```

Finally run `powertagd -d /dev/xxx` to start processing the PowerTags readings.

## Units

- voltage: V
- current: A
- active_power: W
- apparent_power: VA
- reactive_power: VAR
- power_factor: -100% to +100%
- energy: kWh

## InfluxDB

`powertagd` has built-in support to send metrics directly to InfluxDB:
```
powertagd -d /dev/xxx -o influxdb \
  --url http://127.0.0.1:8086 \
  --org <OrgName> \
  --bucket <BucketName> \
  --token <XXX>
```

Below some sample Flux queries for InfluxDB/Grafana.

### Get power values for a specific PowerTag id
```
from(bucket: "powertag")
  |> range(start: v.timeRangeStart, stop:v.timeRangeStop)
  |> filter(fn: (r) => r.id == "0x12345678" and r._field == "total_power_active")
  |> aggregateWindow(every: v.windowPeriod, fn: mean)
```
Where "powertag" is the bucket name and 0x12345678 is the PowerTag id.

### Get daily energy usage for the past 30 days
```
import "date"
import "timezone"

option location = timezone.location(name: "Europe/Paris")

start = date.truncate(t: -30d, unit: 1d)
stop = date.truncate(t: 1d, unit: 1d)

from(bucket: "powertag")
  |> range(start: start, stop: stop)
  |> filter(fn: (r) => r.id == "0x12345678" and r._field == "total_energy_rx")
  |> aggregateWindow(every: 1d, fn: spread, createEmpty: true)
  |> timeShift(duration: -1s)

```


## TODO

- Improve ash protocol error handling
- Finish MQTT support
