# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A collection of standalone Python scripts (and one shell script) for DNS operations, diagnostics, and automation. Scripts manage BIND nameserver zones, test DNSSEC, handle DNS-over-TLS certificates, and perform DNS diagnostics. There is no build system, test suite, or package manager — each script is run directly.

## Running Scripts

All Python scripts are standalone CLI tools run with `python3 <script>.py` (or directly if executable). Most use `argparse` for CLI flags — run with `--help` to see options. No virtual environment or requirements.txt exists; dependencies are installed system-wide.

## Key Dependencies

- **dnspython** (`dns.*`): Used by most scripts for DNS queries, TSIG-authenticated updates, zone transfers
- **boto3**: Used by `nsset-maintainer.py` for AWS ECS integration
- **dnslib**: Used by `dns-ip-responder.py` (a standalone DNS server that echoes client IP)
- **certbot** / **openssl**: External binaries called by `dotls-certmgr.py`
- **requests**: Used by `dynamic-ip-maintainer.py` for external IP lookup

## Script Categories

**Zone/NS Management** — Scripts that modify DNS records via TSIG-authenticated dynamic updates or `rndc`:
- `nsset-maintainer.py` — Syncs NS records from AWS ECS cluster state
- `rndc-modzone-batch.py` — Batch `rndc modzone` operations; reads `config.json` for rndc/catalog settings
- `dynamic-ip-maintainer.py` — Updates A records when external IP changes

**Diagnostics/Testing** — Read-only inspection tools:
- `auth-ns-tester.py` — Comprehensive domain diagnostics (glue vs auth NS, SOA serial consistency, TCP/UDP)
- `dnssec-sync-checker.py` — Verifies DS/DNSKEY synchronization between parent and child
- `rr-edns-tester.py` — Queries all RR types against a server, tests EDNS support
- `dot-cert-tester.py` — Queries via DNS-over-TLS and shows certificate details

**Certificate Management**:
- `dotls-certmgr.py` — Let's Encrypt cert lifecycle for BIND DoT (renewal, archival, symlink rotation, BIND reload). Config: TOML format, see `dotls-certmgr.cfg.example`

## Configuration Patterns

- `config.json` — Used by `rndc-modzone-batch.py` (rndc connection, catalog zone TSIG, domain list)
- `dotls-certmgr.cfg` — TOML config for cert manager (see `.cfg.example`)
- `nsset-maintainer.conf` — INI format with TSIG credentials, referenced from `~/.nsset-maintainer.conf`
- `mounts.cfg` — Maps config files to sandbox paths (used for container deployment)
- `~/.tsigkeyring` — TSIG credentials file (INI format) used by `nsset-maintainer.py`

## Conventions

- Scripts use `#!/usr/bin/env python3` (or `#!/usr/bin/python3`); target Python 3.10+
- DNS operations use dnspython's low-level API (`dns.query`, `dns.message`, `dns.update`) rather than the high-level resolver where direct server control is needed
- TSIG authentication is used for all dynamic update operations
- The `archive/` directory contains timestamped cert/key backups managed by `dotls-certmgr.py`
