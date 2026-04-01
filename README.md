# dns-scripts

A collection of standalone Python scripts for DNS operations, diagnostics, and automation. Scripts manage BIND nameserver zones, verify DNSSEC, handle DNS-over-TLS certificates, and perform DNS diagnostics.

All scripts require Python 3.10+ and are run directly — no build system or virtual environment needed.

## Diagnostics & Testing

### auth-ns-tester.py

Comprehensive DNS domain diagnostics. Queries parent zone for NS delegation (glue records), queries authoritative nameservers directly, compares results, tests each nameserver over both TCP and UDP, and verifies SOA serial consistency.

```
python3 auth-ns-tester.py [-v] [-4|-6] <domain>
```

**Dependencies:** dnspython

### dnssec-sync-checker.py

Verifies DNSSEC deployment by checking DS/DNSKEY synchronization between parent and child nameservers. Calculates DS from DNSKEY and compares with published DS records. Supports batch checking via a file of domains.

```
python3 dnssec-sync-checker.py [-t] <domain>
python3 dnssec-sync-checker.py -f domains.txt [-t]
```

**Dependencies:** dnspython

### dot-cert-tester.py

Queries a DNS server over DNS-over-TLS (DoT) and displays the server's TLS certificate details. Useful for verifying DoT deployment and certificate validity.

```
python3 dot-cert-tester.py [server] [domain] [-p PORT] [-t {A,AAAA}] [-k]
```

Defaults to server `9.9.9.9` and domain `devries.tv`.

**Dependencies:** None (stdlib only)

### rr-edns-tester.py

Queries all DNS resource record types against a server for a given FQDN. Optionally tests EDNS version support (versions 0-100).

```
python3 rr-edns-tester.py -s <server> -f <fqdn> [--edns-test] [-q]
```

**Dependencies:** dnspython

## Zone & NS Management

### nsset-maintainer.py

Syncs NS records for a domain based on running tasks in an AWS ECS cluster. Discovers container IPs via boto3 and adds/removes NS records using TSIG-authenticated dynamic DNS updates.

```
python3 nsset-maintainer.py
```

**Config:** Reads `~/.nsset-maintainer.conf` (INI format) for TSIG credentials and ECS cluster details.

**Dependencies:** dnspython, boto3

### dynamic-ip-maintainer.py

Updates DNS A records when the host's external IP address changes. Detects the current external IP via an HTTP service and issues TSIG-authenticated dynamic updates.

```
python3 dynamic-ip-maintainer.py
```

**Config:** Reads `/tmp/nsset-maintainer.conf` (INI format) for TSIG credentials.

**Dependencies:** dnspython, requests

## Certificate Management

### dotls-certmgr.py

Manages Let's Encrypt TLS certificates for BIND DNS-over-TLS. Handles renewal via DNS-01 challenge (certbot), archives cert/key files with timestamps, atomically rotates symlinks referenced by BIND, and optionally reloads the nameserver.

Designed to run daily via cron or systemd timer.

```
python3 dotls-certmgr.py --config <config.toml> [--dry-run] [--force]
```

**Config:** TOML format — see `dotls-certmgr.cfg.example` for a complete example.

**Dependencies:** certbot, openssl (external binaries)
