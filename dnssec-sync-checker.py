#!/usr/bin/env python3
"""
DNSSEC DS/DNSKEY Synchronization Checker

This script verifies DNSSEC deployment status by:
- Querying parent nameservers for DS records
- Querying child nameservers for KSK DNSKEY records
- Calculating DS from DNSKEY and comparing with published DS records
- Reporting synchronization status across all nameservers
"""

import argparse
import sys
import hashlib
import base64
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.name
import dns.flags
from typing import Optional, Dict, Set, List, Tuple
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class DSRecord:
    """Represents a DS record."""
    key_tag: int
    algorithm: int
    digest_type: int
    digest: str
    nameserver: str  # Which nameserver reported this


@dataclass
class DNSKEYRecord:
    """Represents a DNSKEY record (KSK only)."""
    flags: int
    protocol: int
    algorithm: int
    public_key: str
    key_tag: int
    nameserver: str  # Which nameserver reported this


def get_parent_zone(domain: str) -> str:
    """Get the parent zone for a domain."""
    parts = domain.rstrip('.').split('.')
    if len(parts) <= 1:
        return '.'
    return '.'.join(parts[1:]) + '.'


def get_parent_nameservers(domain: str) -> List[Tuple[str, str]]:
    """
    Get parent zone nameservers with their IPs.
    Returns list of (hostname, ip) tuples.
    """
    domain = domain.rstrip('.') + '.'
    parent = get_parent_zone(domain)
    nameservers = []

    try:
        # Find parent zone nameservers
        parent_ns_answer = dns.resolver.resolve(parent, 'NS')

        for rr in parent_ns_answer:
            ns_hostname = str(rr.target).rstrip('.')
            try:
                # Resolve parent NS to IP (try IPv4 first)
                ip_answer = dns.resolver.resolve(ns_hostname, 'A')
                ns_ip = str(ip_answer[0])
                nameservers.append((ns_hostname, ns_ip))
            except Exception:
                # Try IPv6 if IPv4 fails
                try:
                    ip_answer = dns.resolver.resolve(ns_hostname, 'AAAA')
                    ns_ip = str(ip_answer[0])
                    nameservers.append((ns_hostname, ns_ip))
                except Exception:
                    print(f"  Warning: Could not resolve parent nameserver {ns_hostname}")
                    continue

    except Exception as e:
        print(f"  Error: Could not query parent zone nameservers: {e}")

    return nameservers


def get_child_nameservers(domain: str) -> List[Tuple[str, str]]:
    """
    Get child zone nameservers with their IPs.
    Returns list of (hostname, ip) tuples.
    """
    domain = domain.rstrip('.') + '.'
    nameservers = []

    try:
        # Query for NS records
        ns_answer = dns.resolver.resolve(domain, 'NS')

        for rr in ns_answer:
            ns_hostname = str(rr.target).rstrip('.')
            try:
                # Resolve NS to IP (try IPv4 first)
                ip_answer = dns.resolver.resolve(ns_hostname, 'A')
                ns_ip = str(ip_answer[0])
                nameservers.append((ns_hostname, ns_ip))
            except Exception:
                # Try IPv6 if IPv4 fails
                try:
                    ip_answer = dns.resolver.resolve(ns_hostname, 'AAAA')
                    ns_ip = str(ip_answer[0])
                    nameservers.append((ns_hostname, ns_ip))
                except Exception:
                    print(f"  Warning: Could not resolve child nameserver {ns_hostname}")
                    continue

    except Exception as e:
        print(f"  Error: Could not query child zone nameservers: {e}")

    return nameservers


def query_ds_records(domain: str, ns_hostname: str, ns_ip: str) -> List[DSRecord]:
    """Query DS records from a specific nameserver."""
    domain = domain.rstrip('.') + '.'
    ds_records = []

    try:
        query = dns.message.make_query(domain, dns.rdatatype.DS)
        response = dns.query.udp(query, ns_ip, timeout=5)

        # Check if response is truncated, retry with TCP if needed
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(query, ns_ip, timeout=5)

        # Look for DS records in answer or authority section
        for rrset in list(response.answer) + list(response.authority):
            if rrset.rdtype == dns.rdatatype.DS:
                for rr in rrset:
                    ds_records.append(DSRecord(
                        key_tag=rr.key_tag,
                        algorithm=rr.algorithm,
                        digest_type=rr.digest_type,
                        digest=rr.digest.hex().upper(),
                        nameserver=ns_hostname
                    ))
    except Exception as e:
        print(f"  Warning: Failed to query DS from {ns_hostname} ({ns_ip}): {e}")

    return ds_records


def calculate_key_tag(flags: int, protocol: int, algorithm: int, key_data: bytes) -> int:
    """Calculate key tag for a DNSKEY as per RFC 4034."""
    # Construct the RDATA
    rdata = bytearray()
    rdata.extend(flags.to_bytes(2, 'big'))
    rdata.extend(protocol.to_bytes(1, 'big'))
    rdata.extend(algorithm.to_bytes(1, 'big'))
    rdata.extend(key_data)

    # Calculate key tag
    if algorithm == 1:  # RSA/MD5 (deprecated, but handle it)
        ac = int.from_bytes(rdata[-3:-1], 'big')
    else:
        ac = 0
        for i in range(len(rdata)):
            if i % 2 == 0:
                ac += rdata[i] << 8
            else:
                ac += rdata[i]
        ac += (ac >> 16) & 0xFFFF

    return ac & 0xFFFF


def query_dnskey_records(domain: str, ns_hostname: str, ns_ip: str) -> List[DNSKEYRecord]:
    """Query DNSKEY records (KSK only) from a specific nameserver."""
    domain = domain.rstrip('.') + '.'
    dnskey_records = []

    try:
        query = dns.message.make_query(domain, dns.rdatatype.DNSKEY)
        response = dns.query.udp(query, ns_ip, timeout=5)

        # Check if response is truncated, retry with TCP if needed
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(query, ns_ip, timeout=5)

        # Look for DNSKEY records
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                for rr in rrset:
                    # Only process KSK (Key Signing Keys) - flag 257
                    # KSK has the Secure Entry Point (SEP) bit set (bit 0 of flags)
                    if rr.flags == 257:
                        # The key is already binary data in dnspython
                        key_data = rr.key
                        key_tag = calculate_key_tag(rr.flags, rr.protocol, rr.algorithm, key_data)

                        # Store as base64 for comparison later
                        public_key_b64 = base64.b64encode(key_data).decode('ascii')

                        dnskey_records.append(DNSKEYRecord(
                            flags=rr.flags,
                            protocol=rr.protocol,
                            algorithm=rr.algorithm,
                            public_key=public_key_b64,
                            key_tag=key_tag,
                            nameserver=ns_hostname
                        ))
    except Exception as e:
        print(f"  Warning: Failed to query DNSKEY from {ns_hostname} ({ns_ip}): {e}")

    return dnskey_records


def calculate_ds_from_dnskey(domain: str, dnskey: DNSKEYRecord, digest_type: int) -> str:
    """Calculate DS digest from DNSKEY record."""
    domain = domain.rstrip('.') + '.'

    # Construct the DNSKEY owner name in wire format
    owner_name = dns.name.from_text(domain).to_wire()

    # Construct DNSKEY RDATA
    key_data = base64.b64decode(dnskey.public_key)
    rdata = bytearray()
    rdata.extend(dnskey.flags.to_bytes(2, 'big'))
    rdata.extend(dnskey.protocol.to_bytes(1, 'big'))
    rdata.extend(dnskey.algorithm.to_bytes(1, 'big'))
    rdata.extend(key_data)

    # Concatenate owner name and RDATA
    data_to_hash = owner_name + bytes(rdata)

    # Calculate digest based on digest type
    if digest_type == 1:  # SHA-1
        digest = hashlib.sha1(data_to_hash).hexdigest().upper()
    elif digest_type == 2:  # SHA-256
        digest = hashlib.sha256(data_to_hash).hexdigest().upper()
    elif digest_type == 4:  # SHA-384
        digest = hashlib.sha384(data_to_hash).hexdigest().upper()
    else:
        raise ValueError(f"Unsupported digest type: {digest_type}")

    return digest


def check_dnssec_sync(domain: str) -> bool:
    """
    Check DNSSEC DS/DNSKEY synchronization for a domain.
    Returns True if all checks pass, False otherwise.
    """
    domain = domain.lower().rstrip('.')
    print(f"\n{'='*70}")
    print(f"DNSSEC DS/DNSKEY Synchronization Check for: {domain}")
    print(f"{'='*70}\n")

    all_ok = True

    # Step 1: Get parent nameservers
    print("[1] Finding parent zone nameservers...")
    parent_ns = get_parent_nameservers(domain)

    if not parent_ns:
        print("  ERROR: Could not find parent zone nameservers")
        return False

    print(f"  Found {len(parent_ns)} parent nameserver(s):")
    for ns_hostname, ns_ip in parent_ns:
        print(f"    - {ns_hostname} ({ns_ip})")
    print()

    # Step 2: Query DS records from each parent nameserver
    print("[2] Querying DS records from parent nameservers...")
    all_ds_records = []
    ds_by_nameserver = defaultdict(list)

    for ns_hostname, ns_ip in parent_ns:
        ds_records = query_ds_records(domain, ns_hostname, ns_ip)
        all_ds_records.extend(ds_records)
        ds_by_nameserver[ns_hostname] = ds_records

        if ds_records:
            print(f"  {ns_hostname}:")
            for ds in ds_records:
                digest_type_name = {1: 'SHA-1', 2: 'SHA-256', 4: 'SHA-384'}.get(ds.digest_type, f'Type-{ds.digest_type}')
                print(f"    KeyTag={ds.key_tag} Alg={ds.algorithm} DigestType={ds.digest_type}({digest_type_name})")
                print(f"    Digest={ds.digest}")
        else:
            print(f"  {ns_hostname}: No DS records found")

    if not all_ds_records:
        print("\n  WARNING: No DS records found on any parent nameserver")
        print("  This domain may not have DNSSEC enabled.")
        all_ok = False

    # Check consistency across parent nameservers
    if len(ds_by_nameserver) > 1:
        print("\n  DS Record Consistency Check:")
        first_ns = list(ds_by_nameserver.keys())[0]
        first_ds_set = set((ds.key_tag, ds.algorithm, ds.digest_type, ds.digest)
                           for ds in ds_by_nameserver[first_ns])

        all_consistent = True
        for ns_hostname, ds_list in ds_by_nameserver.items():
            if ns_hostname == first_ns:
                continue
            ds_set = set((ds.key_tag, ds.algorithm, ds.digest_type, ds.digest) for ds in ds_list)
            if ds_set != first_ds_set:
                print(f"  ✗ MISMATCH: {ns_hostname} has different DS records than {first_ns}")
                all_consistent = False
                all_ok = False

        if all_consistent and all_ds_records:
            print(f"  ✓ All parent nameservers have consistent DS records")
    print()

    # Step 3: Get child nameservers
    print("[3] Finding child zone nameservers...")
    child_ns = get_child_nameservers(domain)

    if not child_ns:
        print("  ERROR: Could not find child zone nameservers")
        return False

    print(f"  Found {len(child_ns)} child nameserver(s):")
    for ns_hostname, ns_ip in child_ns:
        print(f"    - {ns_hostname} ({ns_ip})")
    print()

    # Step 4: Query DNSKEY records from each child nameserver
    print("[4] Querying KSK DNSKEY records from child nameservers...")
    all_dnskey_records = []
    dnskey_by_nameserver = defaultdict(list)

    for ns_hostname, ns_ip in child_ns:
        dnskey_records = query_dnskey_records(domain, ns_hostname, ns_ip)
        all_dnskey_records.extend(dnskey_records)
        dnskey_by_nameserver[ns_hostname] = dnskey_records

        if dnskey_records:
            print(f"  {ns_hostname}:")
            for dnskey in dnskey_records:
                print(f"    KeyTag={dnskey.key_tag} Flags={dnskey.flags} Alg={dnskey.algorithm}")
        else:
            print(f"  {ns_hostname}: No KSK DNSKEY records found")

    if not all_dnskey_records:
        print("\n  WARNING: No KSK DNSKEY records found on any child nameserver")
        print("  This domain may not have DNSSEC enabled.")
        all_ok = False

    # Check consistency across child nameservers
    if len(dnskey_by_nameserver) > 1:
        print("\n  DNSKEY Record Consistency Check:")
        first_ns = list(dnskey_by_nameserver.keys())[0]
        first_dnskey_set = set((dk.key_tag, dk.algorithm, dk.public_key)
                               for dk in dnskey_by_nameserver[first_ns])

        all_consistent = True
        for ns_hostname, dnskey_list in dnskey_by_nameserver.items():
            if ns_hostname == first_ns:
                continue
            dnskey_set = set((dk.key_tag, dk.algorithm, dk.public_key) for dk in dnskey_list)
            if dnskey_set != first_dnskey_set:
                print(f"  ✗ MISMATCH: {ns_hostname} has different DNSKEY records than {first_ns}")
                all_consistent = False
                all_ok = False

        if all_consistent and all_dnskey_records:
            print(f"  ✓ All child nameservers have consistent DNSKEY records")
    print()

    # Step 5: Compare DS and DNSKEY records
    if all_ds_records and all_dnskey_records:
        print("[5] Verifying DS/DNSKEY synchronization...")

        # Create unique sets for comparison
        unique_ds = {}
        for ds in all_ds_records:
            key = (ds.key_tag, ds.algorithm, ds.digest_type)
            if key not in unique_ds:
                unique_ds[key] = ds

        unique_dnskey = {}
        for dnskey in all_dnskey_records:
            key = (dnskey.key_tag, dnskey.algorithm)
            if key not in unique_dnskey:
                unique_dnskey[key] = dnskey

        # Check each DS record against DNSKEY records
        print("\n  DS Record Validation:")
        for (key_tag, algorithm, digest_type), ds in unique_ds.items():
            dnskey_key = (key_tag, algorithm)

            if dnskey_key not in unique_dnskey:
                print(f"  ✗ DS record (KeyTag={key_tag}, Alg={algorithm}) has no matching DNSKEY")
                all_ok = False
            else:
                # Calculate DS from DNSKEY and compare
                dnskey = unique_dnskey[dnskey_key]
                try:
                    calculated_digest = calculate_ds_from_dnskey(domain, dnskey, digest_type)

                    if calculated_digest == ds.digest:
                        digest_type_name = {1: 'SHA-1', 2: 'SHA-256', 4: 'SHA-384'}.get(digest_type, f'Type-{digest_type}')
                        print(f"  ✓ DS (KeyTag={key_tag}, Alg={algorithm}, {digest_type_name}) matches DNSKEY")
                    else:
                        print(f"  ✗ DS (KeyTag={key_tag}, Alg={algorithm}) MISMATCH:")
                        print(f"    Published DS:  {ds.digest}")
                        print(f"    Calculated DS: {calculated_digest}")
                        all_ok = False
                except Exception as e:
                    print(f"  ✗ Error calculating DS for KeyTag={key_tag}: {e}")
                    all_ok = False

        # Check for DNSKEY records without DS records
        print("\n  DNSKEY Coverage Check:")
        for (key_tag, algorithm), dnskey in unique_dnskey.items():
            has_ds = any((key_tag, algorithm, dt) in unique_ds for dt in [1, 2, 4])

            if not has_ds:
                print(f"  ✗ DNSKEY (KeyTag={key_tag}, Alg={algorithm}) has no corresponding DS record")
                all_ok = False
            else:
                print(f"  ✓ DNSKEY (KeyTag={key_tag}, Alg={algorithm}) has corresponding DS record(s)")

    # Summary
    print(f"\n{'='*70}")
    if all_ok:
        print("RESULT: DS/DNSKEY records are IN SYNC ✓")
    else:
        print("RESULT: DS/DNSKEY records are OUT OF SYNC ✗")
    print(f"{'='*70}\n")

    return all_ok


def main():
    parser = argparse.ArgumentParser(
        description='DNSSEC DS/DNSKEY Synchronization Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s cloudflare.com

This tool will:
  1. Query parent zone nameservers for DS records
  2. Verify DS record consistency across parent nameservers
  3. Query child zone nameservers for KSK DNSKEY records
  4. Verify DNSKEY record consistency across child nameservers
  5. Calculate DS from DNSKEY and verify they match
  6. Report synchronization status
        """
    )
    parser.add_argument('domain', help='Domain name to check (e.g., example.com)')

    args = parser.parse_args()

    # Basic domain validation
    domain = args.domain.strip().lower()
    if not domain or domain.startswith('.') or '..' in domain:
        print(f"Error: Invalid domain name: {args.domain}", file=sys.stderr)
        sys.exit(1)

    try:
        success = check_dnssec_sync(domain)
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
