# powershell-doh-proxy

A local HTTP proxy written in pure PowerShell 5.1 (no dependencies, no admin required) that resolves hostnames through **DNS-over-HTTPS** and tunnels traffic to the real IP, bypassing poisoned DNS / sinkhole block pages. Optionally splits the TLS `ClientHello` across several TCP segments to defeat naive SNI inspection.

## Why

Some networks redirect blocked domains to a sinkhole resolver:

| Lookup | Poisoned answer | Real answer (via DoH) |
|---|---|---|
| `A` | `160.22.222.218-222` (block page server) | `186.2.163.20` |
| `AAAA` | `::1` | — |

Connecting to the sinkhole IP returns the block page with a fake certificate. Connecting to the real IP with a valid `SNI` works fine — so the fix is the resolver, not packet crafting.

## Features

- **DoH resolver** — `dns.google`, fallback `cloudflare-dns.com`, then system DNS; results cached per process
- **HTTP `CONNECT` proxy** — TLS stays end-to-end, your browser validates the real certificate
- **Plain HTTP forwarding** for non-TLS requests
- **Optional `ClientHello` fragmentation** (`-Fragment`) — first payload written in N chunks with a delay, for middleboxes that only inspect the first packet
- **Concurrency** via a runspace pool (32 workers), no extra threads/modules
- **`-Test`** — self-test that prints certificate subject, issuer and page title
- **`-VerboseLog`** — streams `host -> ip:port` log lines to stdout
- **`-SetSystemProxy` / `-ClearSystemProxy`** — toggle the WinINET system proxy

## Requirements

- Windows PowerShell **5.1** or newer
- Outbound HTTPS to `dns.google` / `cloudflare-dns.com`

## Usage

```powershell
# start the proxy
powershell -ExecutionPolicy Bypass -File .\Start-DoHProxy.ps1

# self-test (prints cert + page title, proves the block is bypassed)
powershell -ExecutionPolicy Bypass -File .\Start-DoHProxy.ps1 -Test

# verbose log to stdout, custom port, fragment ClientHello
.\Start-DoHProxy.ps1 -VerboseLog -Port 8080 -Fragment -DelayMs 60

# toggle Windows system proxy (WinINET apps)
.\Start-DoHProxy.ps1 -SetSystemProxy
.\Start-DoHProxy.ps1 -ClearSystemProxy
```

Point your client at the proxy:

```text
chrome.exe --proxy-server=http://127.0.0.1:8080
edge.exe   --proxy-server=http://127.0.0.1:8080
Firefox    -> Settings > Network Settings > Manual proxy: 127.0.0.1 port 8080
curl.exe   -x http://127.0.0.1:8080 https://example.com/
```

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Bind` | `127.0.0.1` | Listen address |
| `-Port` | `8080` | Listen port |
| `-DNS` | `DoH` | `DoH` or `System` |
| `-Fragment` | off | Split the first client payload (TLS `ClientHello`) |
| `-SplitAt` | `1,6` | Byte offsets for the split |
| `-DelayMs` | `40` | Delay between segments |
| `-Test` | off | Run self-test and exit |
| `-VerboseLog` | off | Stream proxy log to stdout |
| `-SetSystemProxy` | off | Enable system proxy on this port |
| `-ClearSystemProxy` | off | Disable system proxy |

## How it works

```text
browser ──HTTP CONNECT──> 127.0.0.1:8080 ──resolve via DoH──> real IP:443
                              │
                              ├─ cache lookup (per hostname)
                              ├─ optional: write ClientHello in chunks (+ delay)
                              └─ relay bytes both ways (poll loop)
```

1. Client sends `CONNECT host:port`.
2. Proxy resolves `host` through DoH (bypassing the local resolver), caches the answer.
3. Proxy opens a TCP tunnel to the resolved IP; the browser performs the TLS handshake end-to-end, so certificate validation stays intact.
4. With `-Fragment`, the first payload is written as several small segments so a first-packet SNI matcher sees no hostname.

## Notes

- Fragmentation only helps middleboxes that inspect a single packet; a DPI that fully reassembles the flow will still see the `SNI`.
- The proxy does not terminate TLS — there is no MITM and no local CA to install.
- `-SetSystemProxy` only affects WinINET-based applications; Chrome/Edge/Firefox may need the flag/setting above.
