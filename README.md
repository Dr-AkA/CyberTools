# PortScanner

`portscanner` — Advanced multithreaded TCP port scanner with optional banner grabbing and JSON output.

> Lightweight, single-file Python 3 scanner designed for fast port sweeps and basic banner grabbing. Useful for quick service discovery during troubleshooting and lab work.

---

## Features

- Resolve hostname → IPv4 address.
- Scan individual ports, comma lists, and ranges (e.g. `22,80,443` or `1-1024`).
- Highly concurrent using `ThreadPoolExecutor` (configurable thread count).
- Optional banner grabbing (first 1024 bytes).
- Pretty-printed summary or machine-friendly JSON output.
- Minimal dependencies (standard library only).

---

## Requirements

- Python 3.7+ (tested on 3.8 / 3.10)
- No third-party packages required.

---

## Installation

Clone or download the repository and make the script executable:

```bash
git clone https://github.com/<youruser>/<repo>.git
cd <repo>
chmod +x portscanner.py   # if you want to run it directly
```

Or run using `python3`:

```bash
python3 portscanner.py -H example.com -p 22,80,443
```

---

## Usage

```
usage: portscanner.py [-h] -H HOST -p PORTS [-t THREADS] [--banner] [--json]

Advanced multithreaded port scanner with banner grabbing.

options:
  -H, --host       Target hostname or IP (required)
  -p, --ports      Ports (e.g. 22,80,443 or 1-1024) (required)
  -t, --threads    Maximum number of threads (default: 200)
  --banner         Attempt to grab service banners
  --json           Output results in JSON format
```

### Examples

Scan common ports:

```bash
python3 portscanner.py -H example.com -p 22,80,443
```

Scan range 1–1024 using 100 threads and grab banners:

```bash
python3 portscanner.py -H 192.0.2.10 -p 1-1024 -t 100 --banner
```

Get JSON machine-readable output:

```bash
python3 portscanner.py -H example.com -p 22,80,443 --json > scan-result.json
```

---

## Output

Pretty summary (default):

```
=== Scan Summary ===
Host: example.com (93.184.216.34)
Open Ports: 2
  Port 22 - OPEN | Banner: SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2
  Port 80 - OPEN | Banner: HTTP/1.1 200 OK
```

JSON output (when `--json`):

```json
{
  "host": "example.com",
  "ip": "93.184.216.34",
  "ports": [
    {
      "port": 22,
      "status": "open",
      "banner": "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"
    },
    {
      "port": 80,
      "status": "open"
    }
  ]
}
```

---

## Design notes & limitations

- Uses **TCP connect** to determine port status (fast and reliable for open/closed detection).
- Banner grabbing: sends `\r\n` then reads up to 1024 bytes. Some services require protocol-specific probes; banner grabbing may not return meaningful data for all services.
- Threading: default `MAX_THREADS=200`. Adjust `-t` based on target/latency and your network limits.
- IPv6 not handled — only IPv4 name resolution and sockets.
- No rate limiting or stealth features — intended for authorized/benign scanning.

---

## Safety, legal & responsible use (READ THIS)

Port scanning systems you do not own or do not have explicit authorization to test can be illegal and may get you blocked or reported. Only scan hosts that you:

- Own, or
- Have explicit written permission to test, or
- Are otherwise authorized (e.g., a pentest engagement / bug bounty with permission).

Always coordinate with network owners and obey local laws and terms of service.

---

## Suggested future improvements

- ICMP host discovery (`ping`) before scanning.
- UDP scanning support (requires special handling/timeouts).
- Rate limiting and polite delays to avoid overwhelming targets.
- Protocol-specific banner probes (HTTP, SSH, SMTP, etc.) for richer information.
- Asyncio-based high-scale scanning for improved performance.
- CSV output option, unit tests, and CI checks.

---

## Contributing

- Open issues for bugs or feature requests.
- Pull requests welcome — keep changes minimal and include tests where applicable.

---

## License

This repository is available under the MIT License. See `LICENSE` for details.
