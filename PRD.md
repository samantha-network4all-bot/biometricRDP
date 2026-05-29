# PRD — biometricRDP (a from-scratch RDP client, for macOS)

> **Audience:** an executor LLM ("Agent 007") building this app one
> vertical slice at a time, driven by the 007-builder orchestrator.
> Every design decision is pre-resolved. **Do not invent behavior,
> endpoints, wire formats, or libraries.** If something is unspecified,
> stop and ask the product owner.

---

## 0. Reading order

1. Read §1–§6 once, fully, before writing code.
2. Read **§7 (HTTP test API)** and **§8 (architectural invariants)**
   before *every* slice. The quality review enforces §8 mechanically;
   the feature check exercises §7.
3. Every behavior MUST be reachable from the HTTP test API and MUST obey
   the MVC contract (§8.14 + `.agent/skills/mvc-appkit.md`). A behavior
   reachable only by clicking is, for this project, untestable and
   therefore unbuilt.
4. **This is a from-scratch RDP protocol implementation with no
   third-party libraries.** The two rules that make a networked,
   host-dependent client deterministically testable are non-negotiable:
   the protocol core is **pure and transport-injectable** (§8.2), and
   feature tests run only against the **bundled loopback mock RDP host**
   (§8.15) — never a live Windows machine.

---

## 1. Product Overview

### 1.1 What we are building
A native macOS Remote Desktop client named **biometricRDP** that speaks
the **RDP wire protocol from scratch** (over `Network.framework`, no
third-party RDP library) to connect to real hosts the way `mstsc.exe`
does. It renders the remote desktop, sends keyboard/mouse input,
redirects clipboard/audio/drives/printers, loads and saves **`.rdp`
connection profiles**, and stores credentials in a **Touch ID-gated
encrypted vault**. The HTTP test API can **drive a remote session
end-to-end** — connect, type, click, read the remote screen — which is
the headless "control remote computers" capability.

### 1.2 In scope
- **RDP core (from scratch):** TCP + TLS via `Network.framework`;
  X.224 / MCS connection sequence; **NLA via CredSSP + NTLMv2**;
  capability exchange; **bitmap updates (raw + interleaved RLE)** into a
  decoded framebuffer; **input PDUs** (keyboard scancodes/unicode,
  mouse); fast-path updates/input.
- **Display:** configurable resolution, **16/32-bpp** color depth,
  windowed or full screen.
- **Virtual channels:** clipboard **text** (cliprdr), **audio playback**
  (rdpsnd), **drive + printer redirection** (rdpdr), and mstsc
  **Experience** performance flags.
- **`.rdp` profiles:** parse/serialize the `key:type:value` format;
  save / load / delete / import / export; an mstsc-style settings UI
  (General / Display / Local Resources / Experience / Advanced).
- **Touch ID-gated credential vault:** AES-GCM at rest, key protected by
  the Secure Enclave via LocalAuthentication; connect by `credentialId`.
- **Bundled mock RDP host** (test-only, loopback) for deterministic
  offline verification; doubles as the conformance target per layer.
- An embedded localhost **HTTP test API** (§7) that connects sessions,
  injects input, and reads the remote framebuffer (pixel + screenshot).

### 1.3 Out of scope (deferred, §10)
RemoteFX / NSCodec / H.264 / progressive codecs; Kerberos & smartcard
auth; RD Gateway; multi-monitor; dynamic resolution resize; file/image
clipboard; USB redirection; session recording; real-host CI; custom app
icon.

### 1.4 Success criteria
biometricRDP connects to a real Windows host (TLS + NLA) and drives it
like mstsc; **and every protocol layer and feature is verifiable through
the HTTP test API against the bundled mock host — deterministically and
repeatably, offline.**

---

## 2. Tech Stack (locked, do not deviate)

| Item | Choice |
| --- | --- |
| Language | Swift 5.9+ |
| UI framework | AppKit. SwiftUI permitted for settings panels; the desktop is an AppKit `NSView` drawing the framebuffer. |
| RDP | **Implemented from scratch.** No FreeRDP, no third-party protocol/crypto libraries. |
| Project gen | **XcodeGen** (`Project.yml`). `.xcodeproj` generated each build, git-ignored. |
| Build | `xcodegen generate && xcodebuild -scheme biometricRDP -configuration Debug -derivedDataPath build/ build` |
| Min macOS | 13.0 |
| Architecture | Universal (arm64 + x86_64) |
| Third-party deps | **None.** Standard library, AppKit, SwiftUI, CoreGraphics, `Network.framework`, `Security`/`CryptoKit`/CommonCrypto, `LocalAuthentication`, `AVFoundation` (audio playback). |
| Transport / TLS | `Network.framework` (`NWConnection`, `NWProtocolTLS`). |
| Crypto | `CryptoKit` + CommonCrypto (NTLMv2 = HMAC-MD5/MD4/MD5; vault = AES-GCM + PBKDF2/Secure Enclave). No third-party crypto. |
| HTTP server | Hand-rolled over `Network.framework` (`NWListener`). No web frameworks. |
| Entry point | Explicit `biometricRDP/main.swift` calling `NSApplication.shared.run()`. **No `@main`** (§8.1). |
| Window | Standard titled `NSWindow` with real traffic lights. |
| Bundle ID | `com.bimboware.biometricrdp` |

> NTLMv2 requires MD4 (not in CryptoKit). Implement MD4 in-repo (pure
> Swift) under `RDP/Crypto/`. MD5/HMAC/SHA use CryptoKit/CommonCrypto.

---

## 3. Project Structure

Every user-visible feature is an `NSViewController` that owns its model,
its view, **and its HTTP routes** (§8.14). The **`RDP/` core is pure
Swift and MUST NOT `import AppKit`** (§8.2).

```
biometricRDP/
├── main.swift                          # NSApplication.shared.run()
├── AppDelegate.swift                   # instantiates AppController
│
├── App/
│   ├── AppController.swift             # /healthz, /shutdown, /screenshot
│   ├── MenuBuilder.swift
│   └── TestAPI/ (TestAPIServer, TestAPIRouter, TestAPIRequest+Response)
│
├── Window/
│   ├── WindowController.swift          # /window/list
│   ├── WindowState.swift
│   ├── RDPWindow.swift
│   └── RootView.swift                  # connection bar + desktop view + settings host
│
├── RDP/                                # PURE Swift protocol core — NO AppKit, transport-injectable
│   ├── RDPSession.swift                # connect state machine → active session; drives Framebuffer
│   ├── Transport.swift                 # protocol: send/recv bytes (real = Network.framework; mock injects)
│   ├── NetworkTransport.swift          # Network.framework TCP+TLS implementation of Transport
│   ├── PDU/
│   │   ├── X224.swift  MCS.swift       # connection sequence
│   │   ├── Capabilities.swift          # capability set exchange
│   │   ├── BitmapUpdate.swift          # bitmap update PDU parse
│   │   ├── InputPDU.swift              # keyboard/mouse input PDU encode
│   │   └── FastPath.swift              # fast-path update/input
│   ├── Security/
│   │   ├── CredSSP.swift  NLA.swift    # TSRequest exchange over TLS
│   │   ├── NTLMv2.swift                # NTLMv2 message + MIC computation
│   │   └── Crypto/ (MD4.swift, …)      # in-repo MD4; HMAC/MD5/SHA via system
│   ├── Bitmap/
│   │   ├── Framebuffer.swift           # decoded RGBA remote screen (pure)
│   │   └── BitmapCodec.swift           # raw + interleaved-RLE decode
│   └── Channels/
│       ├── VirtualChannel.swift        # channel framing
│       ├── ClipRDR.swift  RDPSND.swift  RDPDR.swift
│
├── Session/
│   ├── SessionController.swift         # /session/*  (connect,disconnect,state,pixel,screenshot)
│   └── DesktopView.swift               # renders Framebuffer; captures local mouse/keyboard
│
├── Input/
│   └── InputController.swift           # /input/*  (key,type,mouse) → InputPDU on active session
│
├── Clipboard/
│   └── ClipboardController.swift       # /clipboard/*  (get,set) via ClipRDR
│
├── Audio/
│   └── AudioController.swift           # /audio/*  (state) via RDPSND; plays locally (AVAudioEngine)
│
├── Redirection/
│   ├── DrivesController.swift          # /drives/*   (map,list,unmap) via RDPDR
│   └── PrintersController.swift        # /printers/* (list,add)        via RDPDR
│
├── Profiles/
│   ├── ProfilesController.swift        # /profiles/* (list,save,load,delete,import,export)
│   ├── RDPFile.swift                   # .rdp key:type:value parse/serialize (pure)
│   └── SettingsView.swift              # mstsc-like tabs
│
├── Credentials/
│   ├── CredentialsController.swift     # /credentials/* (unlock,lock,save,list,get,delete)
│   ├── Vault.swift                     # AES-GCM vault (pure crypto, no AppKit)
│   └── Biometric.swift                 # LAContext gate + test-unlock path
│
├── MockHost/                           # TEST-ONLY bundled mock RDP host (loopback)
│   ├── MockRDPHost.swift               # speaks the wire protocol; scripted framebuffer; echoes input
│   └── MockController.swift            # /mock/* (start,stop,push,lastInput) — test control
│
└── Theme/ (Metrics, Palette)
```

Do not create files outside this list without a controller home. No
top-level route except `/healthz`, `/shutdown`, `/screenshot` (§7.3).

---

## 4. UI

Native macOS chrome. A **connection bar** (host, profile picker,
Connect/Disconnect) atop a **desktop view** that renders the remote
framebuffer and captures local keyboard/mouse when focused. A
**settings sheet** with mstsc-style tabs (General / Display / Local
Resources / Experience / Advanced) edits the active `.rdp` profile.
Default window `1280 × 800`; the desktop view scales the framebuffer
preserving aspect (no smoothing — 1:1 when sizes match).

---

## 5. RDP behavior

### 5.1 Connection sequence (`RDP/RDPSession.swift`)
`disconnected → tcp → tls → x224 → nla → mcs → capabilities → active`
(or `failed{reason}`). Each step is a parser/serializer in `RDP/PDU` or
`RDP/Security`. `/session/connect` is **synchronous** — it returns only
when the session reaches `active` or `failed` (or a timeout, §8.15).

### 5.2 Security / NLA (`RDP/Security/*`)
Enhanced RDP Security over TLS (`Network.framework` TLS). NLA via
**CredSSP**: a TSRequest exchange carrying **NTLMv2** (NEGOTIATE →
CHALLENGE → AUTHENTICATE) with the public-key/channel-binding MIC, then
the credentials sub-protocol. NTLMv2 uses in-repo MD4 + HMAC-MD5.
Kerberos/smartcard deferred (§10).

### 5.3 Display & bitmap (`RDP/Bitmap/*`)
Negotiate `desktopWidth/Height` and **16 or 32 bpp**. Decode **raw** and
**interleaved-RLE** bitmap updates into `Framebuffer` (an RGBA buffer).
`Framebuffer` is pure and is the single source of truth for
`/session/pixel` and `/session/screenshot`. RemoteFX/NSCodec/H.264
deferred.

### 5.4 Input (`RDP/PDU/InputPDU.swift`, `Input/InputController.swift`)
Encode keyboard (scancode + unicode) and mouse (move/button/wheel) input
PDUs (slow-path and fast-path). The local `DesktopView` and the `/input`
routes funnel through one send path on the active session (§8.3).

### 5.5 Virtual channels (`RDP/Channels/*`)
- **Clipboard (cliprdr):** bidirectional **text** sync. Remote copy →
  local pasteboard; `/clipboard/set` → offer to remote.
- **Audio (rdpsnd):** receive audio format + PCM blocks; play via
  `AVAudioEngine`; expose a received-samples counter for assertions.
- **Drive/printer (rdpdr):** announce mapped local folders/printers;
  serve the remote's file/print I/O requests for mapped drives.
- **Experience flags:** wallpaper/font-smoothing/animation/composition
  /connection-speed bits sent in the client info + capabilities, sourced
  from the `.rdp` profile.

### 5.6 Profiles (`Profiles/*`)
`RDPFile` parses/serializes the mstsc `key:type:value` format (e.g.
`full address:s:host`, `username:s:user`, `desktopwidth:i:1280`,
`desktopheight:i:800`, `session bpp:i:32`, `screen mode id:i:2`,
`audiomode:i:0`, `redirectclipboard:i:1`, `disable wallpaper:i:1`).
Profiles persist as `.rdp` files; save/load/delete/import/export.

### 5.7 Credentials & biometrics (`Credentials/*`)
A single AES-GCM vault. Normal mode: the key is wrapped by a Secure
Enclave key with a **biometric (Touch ID) access control**; using a
saved credential prompts Touch ID via `LAContext`. Test mode: biometrics
are unavailable, so `/credentials/unlock {testSecret}` derives the key
from a test secret instead (§8.16). Connect references a stored
credential by `credentialId` so plaintext need not transit for normal use.

---

## 6. Profile & test isolation
- **Normal mode:** `.rdp` profiles under
  `~/Library/Application Support/biometricRDP/Profiles/`; the credential
  vault alongside, biometric-gated.
- **Test mode** (`BIOMETRICRDP_TEST_API=1`): isolated, empty profiles
  dir + isolated vault under a temp dir, with `/credentials/unlock`
  accepting a test secret (no biometrics). Sessions connect ONLY to the
  bundled loopback mock host. Real profile/vault untouched (§8.7).

---

## 7. Testability (the HTTP test API)

### 7.1 Why
Deterministic, offline verification of a host-dependent protocol client.
The feature check uses HTTP only (never `osascript`/`CGEvent`). Two
rules make it work: synchronous connect (§8.15) and the **bundled mock
RDP host** as the only test target (§8.15).

### 7.2 Enabling the API
- Binds when `BIOMETRICRDP_TEST_API=1` is set. Default off.
- Port is OS-chosen (`:0`) and written to
  `~/Library/Application Support/biometricRDP/test-api.port` (decimal,
  newline-terminated) before accepting connections.
- Handlers run off the main queue; `DispatchQueue.main.sync` before
  touching AppKit. Protocol/decoding runs on a background queue;
  async session events bridge to the synchronous HTTP response with a
  bounded wait. Enabling the API switches to the isolated test profile
  and enables the `/mock` controller (§6).

### 7.3 Required endpoints
Every route is `/<prefix>/<action>`; only `/healthz`, `/shutdown`,
`/screenshot` are top-level. JSON unless noted; errors return
`{"error":"..."}`.

#### App (`AppController`) — top-level orchestrator routes
| Method | Path | Body / Query | Response | Purpose |
|---|---|---|---|---|
| GET | `/healthz` | — | `{"ok":true}` | Readiness |
| POST | `/shutdown` | — | `{"ok":true}` | terminate after responding |
| GET | `/screenshot` | `?region=window` | `image/png` | Window PNG via `cacheDisplay` (the desktop view draws our own framebuffer, so it captures fine; §7.6) |

#### Window (`WindowController`)
| GET | `/window/list` | → `[{"id":"w1","title":"biometricRDP","isKey":true}]` |

#### Mock host (`MockController`) — test-only, loopback
| Method | Path | Body | Response | Purpose |
|---|---|---|---|---|
| POST | `/mock/start` | `{"nla":true,"username":"u","password":"p","width":1280,"height":800,"bpp":32}` | `{"ok":true,"host":"127.0.0.1","port":3389xx}` | Start a deterministic mock RDP host |
| POST | `/mock/stop` | `{}` | `{"ok":true}` | Stop it |
| POST | `/mock/push` | `{"pattern":"solid","color":"#3050A0","rect":[0,0,1280,800]}` | `{"ok":true}` | Push a known framebuffer update to the connected client |
| GET | `/mock/lastInput` | — | `{"keys":[{"scancode":30,"down":true}],"mouse":[{"x":10,"y":20,"button":"left","action":"click"}],"text":"hi"}` | What input the mock received (assert input reached the host) |

#### Session (`SessionController`)
| Method | Path | Body / Query | Response | Purpose |
|---|---|---|---|---|
| POST | `/session/connect` | `{"host":"127.0.0.1","port":3389,"username":"u","password":"p","credentialId":null,"profile":null,"width":1280,"height":800,"bpp":32}` | `{"ok":true,"state":"active","width":1280,"height":800,"bpp":32}` | **Synchronous**: returns at `active`/`failed`/timeout |
| POST | `/session/disconnect` | `{}` | `{"ok":true}` | Tear down |
| GET | `/session/state` | — | `{"state":"active","host":"...","width":1280,"height":800,"bpp":32,"security":"tls+nla"}` | Session state |
| GET | `/session/pixel` | `?x=&y=` | `{"x":10,"y":20,"color":"#3050A0"}` | Framebuffer pixel |
| GET | `/session/screenshot` | — | `image/png` | Remote framebuffer PNG |

#### Input (`InputController`) — acts on the active session
| Method | Path | Body | Response | Purpose |
|---|---|---|---|---|
| POST | `/input/key` | `{"scancode":30,"down":true}` or `{"key":"a","down":true}` | `{"ok":true}` | Keyboard PDU |
| POST | `/input/type` | `{"text":"hello"}` | `{"ok":true}` | Unicode type sequence |
| POST | `/input/mouse` | `{"x":10,"y":20,"button":"left","action":"click","wheel":0}` | `{"ok":true}` | Mouse PDU (action ∈ move/down/up/click) |

#### Clipboard (`ClipboardController`)
| GET | `/clipboard/get` | → `{"text":"copied on remote"}` | last text synced from remote |
| POST | `/clipboard/set` | `{"text":"..."}` → `{"ok":true}` | offer text to remote |

#### Audio (`AudioController`)
| GET | `/audio/state` | → `{"active":true,"format":"pcm_s16le_44100","samplesReceived":12345}` | assert audio data arrived |

#### Drives / Printers (`DrivesController`, `PrintersController`)
| POST | `/drives/map` | `{"localPath":"/tmp/share","name":"share"}` → `{"ok":true}` |
| GET | `/drives/list` | → `[{"name":"share","localPath":"/tmp/share"}]` |
| POST | `/drives/unmap` | `{"name":"share"}` → `{"ok":true}` |
| GET | `/printers/list` | → `[{"name":"PDF"}]` |
| POST | `/printers/add` | `{"name":"PDF"}` → `{"ok":true}` |

#### Profiles (`ProfilesController`)
| GET | `/profiles/list` | → `[{"name":"work"}]` |
| POST | `/profiles/save` | `{"name":"work","fields":{"full address":"host","desktopwidth":1280,"session bpp":32}}` → `{"ok":true}` |
| GET | `/profiles/load` | `?name=work` → `{"fields":{...}}` |
| POST | `/profiles/delete` | `{"name":"work"}` → `{"ok":true}` |
| POST | `/profiles/import` | `{"rdp":"full address:s:host\\n..."}` → `{"ok":true,"name":"host"}` |
| GET | `/profiles/export` | `?name=work` → `{"rdp":"full address:s:host\\n..."}` |

#### Credentials (`CredentialsController`)
| POST | `/credentials/unlock` | `{"testSecret":"t"}` → `{"ok":true}` | biometric in normal mode; test secret in test mode |
| POST | `/credentials/lock` | `{}` → `{"ok":true}` |
| POST | `/credentials/save` | `{"host":"h","username":"u","password":"p"}` → `{"ok":true,"id":"c1"}` |
| GET | `/credentials/list` | → `[{"id":"c1","host":"h","username":"u"}]` | metadata, no plaintext |
| GET | `/credentials/get` | `?id=c1` → `{"password":"p"}` | **test-only** read-back (server runs only in test mode) |
| POST | `/credentials/delete` | `{"id":"c1"}` → `{"ok":true}` |

New behavior MUST belong to a controller — never a top-level route.

### 7.4 Per-issue contract
Each `slice` issue carries an `acceptance:` JSON block of probes.
Example — "connect to the mock host (TLS+NLA) and read a pushed pixel":
```json
{
  "acceptance": [
    {"step": "connect-and-read-screen",
     "calls": [
       {"method":"POST","path":"/mock/start","body":{"nla":true,"username":"u","password":"p","width":1280,"height":800,"bpp":32}},
       {"method":"POST","path":"/session/connect","body":{"host":"127.0.0.1","port":0,"username":"u","password":"p"}},
       {"method":"GET","path":"/session/state","expect":{"state":"active","security":"tls+nla"}},
       {"method":"POST","path":"/mock/push","body":{"pattern":"solid","color":"#3050A0","rect":[0,0,1280,800]}},
       {"method":"GET","path":"/session/pixel?x=10&y=20","expect":{"color":"#3050A0"}}
     ]}
  ]
}
```
(The harness substitutes the mock port returned by `/mock/start`; if your
runner can't thread that value, the mock binds a fixed test port the
client reads from `/mock/start`'s response and `/session/connect` accepts
`"port":0` meaning "use the running mock".) The feature check fails the
issue if any `expect` assertion fails.

### 7.5 Security
Listener binds only to `127.0.0.1`, opt-in via `BIOMETRICRDP_TEST_API=1`.
Credential read-back (`/credentials/get`) is unreachable in shipped
builds (no server). NTLMv2 secrets/passwords never logged.

### 7.6 Self-screenshot
`/screenshot` and `/session/screenshot` use in-process drawing only:
the desktop view renders our own `Framebuffer` (a CG bitmap), captured
via `contentView.bitmapImageRepForCachingDisplay` → `cacheDisplay` (or
the framebuffer exported directly to PNG). NEVER
`CGWindowListCreateImage`/`CGDisplayCreateImage`/`screencapture`.

---

## 8. Architectural invariants

The code-quality review uses this list; any violation blocks the PR.

### 8.1 Entry point
Explicit `biometricRDP/main.swift` builds `NSApplication.shared`, sets
`setActivationPolicy(.regular)`, assigns the delegate, calls `run()`.
`@main` on `NSApplicationDelegate` forbidden.

### 8.2 Pure, transport-injectable protocol core
`RDP/` is pure Swift, no `import AppKit`/`SwiftUI`. `RDPSession` talks to
a `Transport` protocol (send/recv bytes); the real implementation wraps
`Network.framework`, and the mock host injects an in-process transport.
PDU/codec/crypto functions are pure and deterministic (fixture-testable).
`Framebuffer` is a pure RGBA buffer. No global mutable protocol state.

### 8.3 One input path
Local `DesktopView` events and the `/input` routes funnel through one
`InputPDU` send path on the active session. Menu/toolbar invoke the same
session actions. No duplicate input logic.

### 8.4 Image loading
No `NSImage(imageLiteralResourceName:)`; failable `NSImage(named:)` with
a non-trapping fallback.

### 8.5 Callback re-entrancy
A "set session state / set active profile / set framebuffer" method
updates state only; it must not re-emit the request callback for that
same change.

### 8.6 Window
Standard titled `NSWindow` with real traffic lights. Any `.borderless`
subclass overrides `canBecomeKey`/`canBecomeMain`.

### 8.7 Network & test isolation
The client uses `Network.framework` for real connections (it's a remote
client; that's allowed). **Feature tests connect ONLY to the bundled
loopback mock host** — never a live Windows machine. Test mode uses an
isolated profiles dir + vault + test-unlock (no biometrics). The only
listeners are the loopback test server and the test-only mock host.

### 8.8 Force-unwrap discipline
`try!`, `as!`, `!`-on-optionals forbidden except: `NSScreen.main`
(guard + fallback); `URL(string:)` of literals; the screenshot
`bitmapImageRepForCachingDisplay`/`representation` pair (§7.6).
**Wire data is never force-unwrapped** (§8.17).

### 8.9 Test API parity
Every PR adding user-visible behavior extends the owning controller's
routes so it's reachable + assertable via HTTP. No probe path → fails.

### 8.10 Silent failure
`catch { /* ignore */ }` forbidden. Protocol errors set
`session.state = failed{reason}` and surface; never swallowed.

### 8.11 Notifications & observers
`NotificationCenter`/KVO closures capture `self` weakly; observers
removed on session teardown.

### 8.12 Threading
Networking + PDU decoding run on a background queue; `Framebuffer`/AppKit
updates and input on the main queue. Test handlers `DispatchQueue.main`
where touching AppKit; async session events bridge to the HTTP response
with a bounded wait.

### 8.13 Self-screenshot only
`/screenshot` + `/session/screenshot` use only in-process drawing of our
own framebuffer (§7.6). Any `CGWindowList`/`CGDisplay`/`screencapture`/
TCC-gated API is a blocker.

### 8.14 Controller owns its routes (MVC)
Every feature is an `NSViewController` under
`biometricRDP/<Feature>/<Name>Controller.swift`, registering its routes
in `viewDidLoad` (extension, same file). Views never touch
`TestAPIRouter`/`URLSession`. The `RDP/` core never imports AppKit.
Top-level routes only `/healthz`/`/shutdown`/`/screenshot`.

### 8.15 Deterministic sessions & mock host
`/session/connect`, `/session/disconnect`, `/session/reconnect` resolve
only after reaching a terminal state (`active`/`failed`) or a timeout —
never fire-and-forget. **Feature-test probes target only the bundled
mock host on loopback.** PDU/codec/crypto are pure and fixture-tested.

### 8.16 Credential & crypto security
Credentials encrypted at rest with AES-GCM; the key is Secure
Enclave-wrapped with a Touch ID access control (LocalAuthentication).
Plaintext exists only in memory while unlocked and only crosses the
loopback test API in test mode. NTLMv2 hashes, passwords, and TLS keys
are never written to logs/state. Test mode substitutes a test-unlock
secret for biometrics. Implement NTLMv2/MD4 exactly per spec — no ad-hoc
crypto shortcuts.

### 8.17 Wire robustness
All RDP/PDU/channel parsing is bounds-checked: malformed, truncated, or
oversized data from the host (or mock) is rejected and fails the session
cleanly, never crashing or force-unwrapping. Length fields are validated
against the buffer before use.

---

## 9. The orchestrator's contract
(Informational.)
- Issues are labelled `slice`, numbered `S1`, `S2`, …
- `S1` ≈ "app launches via `main.swift`, shows a window with a
  connection bar and an empty desktop, `GET /healthz` → 200,
  `GET /window/list` → one entry, `GET /screenshot` → a PNG."
- Suggested slice ladder: mock host start/stop → TCP connect to mock →
  TLS handshake → X.224/MCS → NTLMv2/CredSSP (NLA) against mock test
  creds → capability exchange → reach `active` + `/session/state` →
  receive a pushed bitmap + decode into framebuffer → `/session/pixel` →
  raw then interleaved-RLE decode → mouse input PDU + `/mock/lastInput` →
  keyboard + `/input/type` → fast-path → `.rdp` profile save/load/import
  → credential vault unlock(test)/save/list → connect by `credentialId`
  → clipboard text → audio samples counter → drive redirection →
  printer → experience flags in client info.
- Each issue cycles `code-agent → xcodebuild → feature-test →
  quality-review`; failure bumps `attempt:N`; at the cap the orchestrator
  hands off for human review.

---

## 10. Out of v1, deferred
RemoteFX/NSCodec/H.264/progressive codecs; Kerberos & smartcard auth; RD
Gateway; multi-monitor; dynamic resolution resize; file/image clipboard;
USB redirection; session recording; reconnect/auto-reconnect tuning;
real-host CI; custom app icon.

End of PRD.
