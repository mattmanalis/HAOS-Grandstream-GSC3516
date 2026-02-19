# HAOS Grandstream GSC3516

Custom HACS integration for controlling and monitoring Grandstream GSC3516 devices in Home Assistant OS.

## Features

- Config flow UI (no YAML required)
- Supports multiple devices (add multiple integration entries)
- Polls status keys from Grandstream CGI API
- Optional volume/mute control through configurable P-value mappings
- Binary sensors for online, SIP registration, in-call, and ringing state
- Services for dialing and hanging up calls
- Native call API support for GSC3516 firmware (`api-make_call`, `api-phone_operation`, `api-get_line_status`)

## Install (HACS)

1. HACS -> Integrations -> Custom repositories
2. Add this repo URL and select `Integration`
3. Install `Grandstream GSC3516`
4. Restart Home Assistant

## Configure

1. Settings -> Devices & Services -> Add Integration
2. Search for `Grandstream GSC3516`
3. Enter host, credentials, and protocol
4. Open integration `Configure` and set options:
   - `Status keys`: keys to poll, separated by `:` or `,`
   - `Volume key/P-value`: key used for volume writes/reads
   - `Mute key/P-value`: key used for mute writes/reads
   - `SIP registered status key`: key that reports registration state
   - `Call status key`: key that reports idle/ringing/in-call state
   - `Use native call API`: recommended for modern GSC3516 firmware
   - `Call API account index`: account to place outbound calls from (for your unit use `0`)
   - `Call API dialplan`: dialplan mode string used by the device (for your unit use `dialing`)
   - `API session SID (optional)`: session token from web UI local storage when needed
   - `Dial/Hangup mappings`: P-values used to start and end calls

## Service calls

Use Home Assistant `Developer Tools -> Actions`.

- `grandstream_gsc3516.dial`
  - `entry_id`: integration entry ID
  - `number`: extension, ring group, or destination
- `grandstream_gsc3516.hangup`
  - `entry_id`: integration entry ID

## Dashboard (integration-native)

Use the integration services directly in scripts/cards.

Do:
- `service: grandstream_gsc3516.dial`
- `service: grandstream_gsc3516.hangup`
- use entity IDs created by this integration (for example `sensor.grandstream_10_200_0_21_call_state`)

Avoid:
- direct `rest_command` calls to `/cgi-bin/api-make_call`
- direct passcode URL calls from Lovelace buttons

Example button actions:

```yaml
type: button
name: Call 6400
icon: mdi:phone
tap_action:
  action: call-service
  service: grandstream_gsc3516.dial
  data:
    entry_id: 01KHT3NT3HC5K4MNGPPDFA0G8K
    number: "6400"
```

```yaml
type: button
name: Hang Up
icon: mdi:phone-hangup
tap_action:
  action: call-service
  service: grandstream_gsc3516.hangup
  data:
    entry_id: 01KHT3NT3HC5K4MNGPPDFA0G8K
```

## Notes

- This integration uses Grandstream web CGI endpoints:
  - `/cgi-bin/dologin`
  - `/cgi-bin/api.values.get`
  - `/cgi-bin/api.values.post`
- Grandstream firmware can vary in available keys/P-values. If a key does not appear, confirm key names from your device firmware.
- If you run HTTPS with a self-signed cert, disable SSL verification in setup.
