# Security Audit: Camera Data Access & Network Exposure

**Date:** 2026-03-14
**Scope:** All routes, services, and code paths that serve, relay, or expose camera data over the network.

---

## 1. Architecture Overview

This application acts as a bridge between Nanit baby cameras (via Nanit's cloud API) and the local network. It:

1. Authenticates with Nanit's remote API (`api.nanit.com`) using email/password or refresh token
2. Opens a WebSocket to Nanit's cloud to command the camera
3. Instructs the camera to push its RTMP stream to a **local RTMP server** run by this application
4. Optionally serves recorded video files over an **HTTP server**
5. Optionally publishes sensor data to an **MQTT broker**

---

## 2. Findings

### FINDING 1: RTMP Server Has No Authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | **CRITICAL** |
| **File** | `pkg/rtmpserver/server.go:21-41, 52-111` |
| **Port** | Default 1935 (configurable via `NANIT_RTMP_ADDR`) |
| **Binding** | `0.0.0.0` (all interfaces) |

**Description:**
The RTMP server accepts any TCP connection and serves live camera streams to any subscriber that knows the baby UID. There is zero authentication — no token, no API key, no credential check.

**Relevant code** (`pkg/rtmpserver/server.go:50-62`):
```go
var rtmpURLRX = regexp.MustCompile(`^/local/([a-z0-9_-]+)$`)

func (s *rtmpHandler) handleConnection(c *rtmp.Conn, nc net.Conn) {
    submatch := rtmpURLRX.FindStringSubmatch(c.URL.Path)
    // ... only validates URL format, no auth check
    babyUID := submatch[1]
    // Immediately starts serving/receiving stream
```

**Attack scenario:**
Anyone on the same LAN (or anyone who can route to the host) can connect to `rtmp://<host>:1935/local/<baby_uid>` with any RTMP client (VLC, ffplay, OBS) and view the live baby camera feed. Baby UIDs are short alphanumeric strings that can be enumerated or obtained from network traffic.

---

### FINDING 2: HTTP Server Has No Authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | **CRITICAL** |
| **File** | `pkg/app/serve.go:15-58` |
| **Port** | 8080 (hardcoded) |
| **Binding** | `0.0.0.0` (all interfaces) |
| **Default state** | Disabled (`HTTPEnabled: false` in `cmd/nanit/main.go:29`) |

**Description:**
When enabled, the HTTP server exposes three unauthenticated endpoints:

| Route | Purpose | Risk |
|-------|---------|------|
| `GET /` | Lists all cameras with embedded `<video>` tags | Reveals baby UIDs and serves live HLS streams |
| `GET /video/*` | Static file server over `/data/video/` | Serves all recorded video files to anyone |
| `POST /log` | Accepts camera log uploads | Arbitrary file write to `/data/log/` |

**Relevant code** (`pkg/app/serve.go:19-28`):
```go
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    // No auth check
    for _, baby := range babies {
        fmt.Fprintf(w, "<video src=\"/video/%v.m3u8\" ...", baby.UID)
    }
})
http.Handle("/video/", http.StripPrefix("/video/", http.FileServer(http.Dir(dataDir.VideoDir))))
```

**Attack scenario:**
Anyone on the LAN can browse to `http://<host>:8080/` and immediately see all camera feeds. The `/video/` endpoint allows downloading any recorded footage. The `/log` endpoint accepts arbitrary POST data and writes it to disk (potential disk-fill DoS).

**Mitigating factor:** HTTP is disabled by default. However, the README encourages users to enable it for HLS streaming, and there is no warning about the security implications.

---

### FINDING 3: Session File Is World-Readable and Contains Plaintext Tokens

| Attribute | Value |
|-----------|-------|
| **Severity** | **HIGH** |
| **File** | `pkg/session/session.go:77` |
| **Location** | `/data/session.json` (default) |

**Description:**
The session file is created with permissions `0644` (owner read/write, group and others read). It contains:

```json
{
  "authToken": "<nanit_access_token>",
  "refreshToken": "<nanit_refresh_token>",
  "babies": [{"uid": "...", "cameraUID": "..."}]
}
```

**Relevant code** (`pkg/session/session.go:77`):
```go
f, err := os.OpenFile(store.Filename, os.O_RDWR|os.O_CREATE, 0644)
```

**Attack scenario:**
Any local user or process on the host can read `/data/session.json` and obtain the Nanit refresh token. This token provides full access to the Nanit account — viewing cameras, accessing recordings, and controlling settings — with no expiration mentioned in the codebase.

---

### FINDING 4: Credentials Passed as Environment Variables

| Attribute | Value |
|-----------|-------|
| **Severity** | **MEDIUM** |
| **File** | `cmd/nanit/main.go:23-25` |

**Description:**
Sensitive credentials are passed via environment variables:
- `NANIT_EMAIL`
- `NANIT_PASSWORD`
- `NANIT_REFRESH_TOKEN`

These are visible in `/proc/<pid>/environ`, `docker inspect`, and process listings.

---

### FINDING 5: RTMP Server Binds to All Interfaces

| Attribute | Value |
|-----------|-------|
| **Severity** | **MEDIUM** |
| **File** | `pkg/rtmpserver/server.go:22`, `cmd/nanit/main.go:48` |

**Description:**
The listen address is derived by extracting only the port from `NANIT_RTMP_ADDR`:

```go
m := regexp.MustCompile("(:[0-9]+)$").FindStringSubmatch(publicAddr)
opts.RTMP = &app.RTMPOpts{
    ListenAddr: m[1],   // e.g., ":1935" — binds to 0.0.0.0
```

Even if a user specifies a specific IP in `NANIT_RTMP_ADDR` (e.g., `192.168.1.10:1935`), only the port is used for binding, so the server always listens on all interfaces.

---

### FINDING 6: No TLS on Local Services

| Attribute | Value |
|-----------|-------|
| **Severity** | **MEDIUM** |
| **Files** | `pkg/app/serve.go:58`, `pkg/rtmpserver/server.go:22` |

**Description:**
Both the HTTP server (`http.ListenAndServe`) and RTMP server (`net.Listen("tcp", ...)`) use plain, unencrypted connections. Camera streams and video files are transmitted in cleartext over the LAN, allowing passive eavesdropping.

---

### FINDING 7: Commented-Out Local WebSocket with Hardcoded IP

| Attribute | Value |
|-----------|-------|
| **Severity** | **LOW** |
| **File** | `pkg/client/websocket.go:103-105` |

**Description:**
```go
// Local
// url := "wss://192.168.3.195:442"
// auth := fmt.Sprintf("token %v", userCamToken)
```

Developer debug code with a hardcoded private IP. Not active, but indicates a direct-to-camera connection path was explored. If uncommented, it would bypass Nanit's cloud auth.

---

### FINDING 8: Trace Logging Exposes Protobuf Messages

| Attribute | Value |
|-----------|-------|
| **Severity** | **LOW** |
| **File** | `cmd/nanit/logger.go` |

**Description:**
At `NANIT_LOG_LEVEL=trace`, all protobuf messages (including sensor data and potentially auth tokens) are logged to stdout. In containerized deployments, this may be persisted in log aggregation systems.

---

## 3. What Is NOT Vulnerable

- **Nanit cloud API communication:** Uses HTTPS/WSS with Bearer token authentication (`pkg/client/rest.go`, `pkg/client/websocket.go:100-112`). Properly authenticated.
- **Remote RTMP stream:** Uses RTMPS with auth token embedded in the URL (`pkg/app/app.go:233`). Encrypted and authenticated.
- **mDNS/UPnP:** No auto-discovery mechanisms found. Services are not advertised to the LAN.
- **MQTT:** Supports username/password authentication and is disabled by default.

---

## 4. Remediation Recommendations

### R1: Add Token-Based Authentication to RTMP Server (Critical)

Add a shared secret / pre-shared key that RTMP subscribers must provide as a query parameter or in the RTMP URL:

```go
// In pkg/rtmpserver/server.go
func (s *rtmpHandler) handleConnection(c *rtmp.Conn, nc net.Conn) {
    // Validate auth token from URL query params
    token := c.URL.Query().Get("token")
    if token == "" || !s.validateToken(token) {
        log.Warn().Msg("Unauthorized RTMP connection attempt")
        nc.Close()
        return
    }
    // ... existing logic
}
```

The token should be configurable via environment variable (e.g., `NANIT_RTMP_TOKEN`) and required for all subscriber connections.

### R2: Add Authentication Middleware to HTTP Server (Critical)

Wrap all HTTP handlers with an auth middleware:

```go
func authMiddleware(token string, next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get("Authorization") != "Bearer "+token {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        next(w, r)
    }
}
```

### R3: Fix Session File Permissions (High)

Change file creation mode from `0644` to `0600`:

```go
// pkg/session/session.go:77
f, err := os.OpenFile(store.Filename, os.O_RDWR|os.O_CREATE, 0600)
```

### R4: Allow Binding to Specific Interface (Medium)

Use the full `NANIT_RTMP_ADDR` for binding instead of extracting only the port, or add a separate `NANIT_RTMP_LISTEN_ADDR` env var:

```go
opts.RTMP = &app.RTMPOpts{
    ListenAddr: utils.EnvVarStr("NANIT_RTMP_LISTEN_ADDR", m[1]),
    PublicAddr: publicAddr,
}
```

### R5: Add TLS Support for Local Services (Medium)

For HTTP, switch to `http.ListenAndServeTLS()` with user-provided certificates. For RTMP, consider wrapping the TCP listener with `tls.NewListener()`, or document that users should front the service with a TLS-terminating reverse proxy.

### R6: Use Docker Secrets Instead of Environment Variables (Medium)

Support reading credentials from files (Docker secrets pattern):

```go
refreshToken := utils.EnvVarStr("NANIT_REFRESH_TOKEN", "")
if refreshToken == "" {
    refreshToken = utils.ReadFileStr("/run/secrets/nanit_refresh_token")
}
```

---

## 5. Summary

| # | Finding | Severity | Default Exposure |
|---|---------|----------|-----------------|
| 1 | RTMP server: no authentication | **CRITICAL** | Enabled by default, all interfaces |
| 2 | HTTP server: no authentication | **CRITICAL** | Disabled by default |
| 3 | Session file world-readable (0644) with plaintext tokens | **HIGH** | Always |
| 4 | Credentials in environment variables | **MEDIUM** | Always |
| 5 | RTMP binds 0.0.0.0 regardless of config | **MEDIUM** | When RTMP enabled |
| 6 | No TLS on local services | **MEDIUM** | When services enabled |
| 7 | Commented-out debug code with hardcoded IP | **LOW** | Not active |
| 8 | Trace logging exposes sensitive data | **LOW** | Only at trace level |

**The most urgent issue is Finding 1:** the RTMP server is enabled by default, binds to all interfaces, and serves live camera feeds without any authentication. Anyone on the same network can watch the camera.
