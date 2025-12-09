# dns-scripts

## dns-verify.py

DNS verification tool that takes a domain name and:
1. Finds all authoritative DNS servers responsible for the domain
2. Queries each nameserver for the SOA (Start of Authority) record
3. Verifies that all nameservers are responding correctly
4. Checks that SOA records are synchronized across all nameservers

### Usage

```bash
./dns-verify.py example.com
./dns-verify.py google.com --verbose
./dns-verify.py cloudflare.com -v
```

### Features

- Automatically discovers authoritative nameservers via NS records
- Resolves nameserver IP addresses (supports both IPv4 and IPv6)
- Queries SOA records directly from each authoritative nameserver
- Compares serial numbers to detect synchronization issues
- Provides clear pass/fail status with detailed reporting
- Verbose mode shows complete SOA record details

### Exit Codes

- `0` - All nameservers responding and SOA records in sync
- `1` - Errors detected (non-responsive servers or out-of-sync SOA)

### Requirements

- Python 3
- dnspython library (`pip install dnspython`)

## nsset-maintainer.py

Checks an ecs cluster and manages a nsset based on the returned results

Requires a ~/.tsigkeyring file with the contents:

`
[TSIG]
name: "name"
key: "<keydata>"
`

## rr-edns-tester.py

Tests DNS record types and EDNS versions for a given domain and server.

