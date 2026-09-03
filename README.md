# TunnelD

Creates RSD tunnels to iOS 17+ devices.

Based off Go-iOS's tunnel service but with a few differences:

- Uses the same tunnel type for all iOS 17+ devices (NCM TCP)
- Doesn't use USBMUX
- Supports on-demand tunnels via WebSocket request
- Only supports Linux and MacOS (no support for Windows)

On macOS, RSD discovery is scoped to Apple USB CDC-NCM interfaces. Built-in
Ethernet, Wi-Fi, and third-party USB network interfaces are ignored. If the USB
registry cannot identify an Apple interface unambiguously, tunneld attempts RSD
discovery on it rather than risk excluding a device interface.

## Getting started

```
% ./tunneld
Usage of ./tunneld:
  -auto-create-tunnels
        Automatically create tunnels for new network interfaces
  -host string
        Host to bind to (default "127.0.0.1")
  -log-level string
        Log level (trace, debug, info, warn, error) (default "info")
  -port int
        Port to listen on (default 60105)
  -version
        Show version information
```

## API

Go-iOS compatible API:

```
GET /health
GET /ready
GET /shutdown
GET /tunnel/<udid>
DELETE /tunnel/<udid>
GET /tunnels
```

Additional API endpoints:

```
GET /status
GET /metrics
GET /services/<udid>
```

WebSocket On-demand API:

```
GET /ws/create-tunnel?udid=<udid>
GET /ws/pause-remoted
```

## Thanks

This project makes use of code from Go-iOS (https://github.com/danielpaulus/go-ios), licensed under the MIT License.
