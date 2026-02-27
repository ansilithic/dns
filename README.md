# dns

![Swift 6.0](https://img.shields.io/badge/Swift-6.0-F05138?logo=swift&logoColor=white)
![macOS 14+](https://img.shields.io/badge/macOS-14%2B-000000?logo=apple&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-blue)

DNS and network configuration inspector for macOS — resolvers, search domains, and interface bindings in a single tree view.

<img src="assets/screenshot.png" alt="dns" width="560">

## How it works

`dns` collects DNS and network state from multiple macOS subsystems (`scutil`, `ipconfig`, `networksetup`, `ifconfig`, `dig`) and renders it as a single color-coded tree. Each section maps to a different layer of the resolution stack:

- **Network** — Active interfaces with IP, subnet, gateway, and an `nmap` scan command
- **DNS Servers** — Per-interface DHCP and manually configured nameservers with reverse DNS
- **Search Domains** — All configured search domains, deduplicated
- **Resolvers** — Per-interface resolver bindings with associated domains
- **mDNS/Bonjour** — Local hostname for multicast DNS
- **Active Directory** — AD domain controllers, Kerberos KDCs, and LDAP endpoints (when joined)

## Install

Requires Swift 6.0+ and macOS 14+. Depends on [swift-cli-core](https://github.com/ansilithic/swift-cli-core) and [swift-argument-parser](https://github.com/apple/swift-argument-parser).

```sh
git clone https://github.com/ansilithic/dns.git
cd dns
make build && make install
```

The binary installs to `/usr/local/bin/dns`.

## Usage

```
USAGE: dns

OPTIONS:
  --version               Show the version.
  -h, --help              Show help information.
```

### Examples

```sh
# Show full DNS and network tree
dns
```

## License

MIT
