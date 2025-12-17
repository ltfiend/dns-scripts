#!/usr/bin/env python3
"""
DNS Domain Diagnostic Tool

This script performs comprehensive DNS diagnostics for a given domain:
- Queries for nameservers from the parent zone (glue records)
- Queries authoritative nameservers directly for NS records
- Compares glue records vs authoritative NS records
- Tests each nameserver over both TCP and UDP
- Verifies SOA serial number consistency across all nameservers
"""

import argparse
import sys
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.name
import dns.flags
from typing import Optional
from dataclasses import dataclass


@dataclass
class NameserverResult:
    """Results from querying a single nameserver."""
    hostname: str
    ip: Optional[str] = None
    udp_works: bool = False
    tcp_works: bool = False
    serial: Optional[int] = None
    error: Optional[str] = None


def get_parent_zone(domain: str) -> str:
    """Get the parent zone for a domain."""
    parts = domain.rstrip('.').split('.')
    if len(parts) <= 1:
        return '.'
    return '.'.join(parts[1:]) + '.'


def get_glue_records(domain: str) -> tuple[set[str], dict[str, set[str]], dict[str, set[str]]]:
    """
    Query the parent zone's nameservers for NS records and glue (A/AAAA) records.
    Returns (set of NS hostnames, dict of hostname -> set of IPv4s, dict of hostname -> set of IPv6s).
    """
    domain = domain.rstrip('.') + '.'
    parent = get_parent_zone(domain)

    ns_hostnames = set()
    glue_ipv4 = {}
    glue_ipv6 = {}

    try:
        # Find parent zone nameservers
        parent_ns_answer = dns.resolver.resolve(parent, 'NS')
        parent_nameservers = [str(rr.target).rstrip('.') for rr in parent_ns_answer]

        # Query a parent nameserver directly for the delegation
        for parent_ns in parent_nameservers:
            try:
                # Resolve parent NS to IP
                parent_ip = str(dns.resolver.resolve(parent_ns, 'A')[0])

                # Create a query for NS records of our domain
                query = dns.message.make_query(domain, dns.rdatatype.NS)
                response = dns.query.udp(query, parent_ip, timeout=5)

                # Extract NS records from authority section (delegation)
                # or answer section if parent is also authoritative
                for rrset in list(response.authority) + list(response.answer):
                    if rrset.rdtype == dns.rdatatype.NS and str(rrset.name).lower() == domain.lower():
                        for rr in rrset:
                            ns_hostnames.add(str(rr.target).rstrip('.').lower())

                # Extract glue records from additional section
                for rrset in response.additional:
                    hostname = str(rrset.name).rstrip('.').lower()
                    if rrset.rdtype == dns.rdatatype.A:
                        if hostname not in glue_ipv4:
                            glue_ipv4[hostname] = set()
                        for rr in rrset:
                            glue_ipv4[hostname].add(str(rr))
                    elif rrset.rdtype == dns.rdatatype.AAAA:
                        if hostname not in glue_ipv6:
                            glue_ipv6[hostname] = set()
                        for rr in rrset:
                            glue_ipv6[hostname].add(str(rr))

                if ns_hostnames:
                    break  # Got what we need

            except Exception as e:
                continue

    except Exception as e:
        print(f"  Warning: Could not query parent zone: {e}")

    return ns_hostnames, glue_ipv4, glue_ipv6


def get_authoritative_ns(domain: str, nameserver_ip: str) -> set[str]:
    """Query a nameserver directly for NS records of the domain."""
    domain = domain.rstrip('.') + '.'
    ns_hostnames = set()
    
    try:
        query = dns.message.make_query(domain, dns.rdatatype.NS)
        query.flags |= dns.flags.RD  # Set recursion desired (though auth servers may ignore)
        response = dns.query.udp(query, nameserver_ip, timeout=5)
        
        for rrset in list(response.answer) + list(response.authority):
            if rrset.rdtype == dns.rdatatype.NS:
                for rr in rrset:
                    ns_hostnames.add(str(rr.target).rstrip('.').lower())
                    
    except Exception as e:
        pass
    
    return ns_hostnames


def resolve_hostname(hostname: str) -> tuple[list[str], list[str]]:
    """Resolve a hostname to its IP addresses.
    Returns (list of IPv4s, list of IPv6s)."""
    ipv4 = []
    ipv6 = []
    try:
        answer = dns.resolver.resolve(hostname, 'A')
        ipv4.extend([str(rr) for rr in answer])
    except Exception:
        pass
    try:
        answer = dns.resolver.resolve(hostname, 'AAAA')
        ipv6.extend([str(rr) for rr in answer])
    except Exception:
        pass
    return ipv4, ipv6


def test_nameserver(domain: str, ns_hostname: str, ns_ip: str) -> NameserverResult:
    """Test a nameserver for UDP/TCP connectivity and get SOA serial."""
    result = NameserverResult(hostname=ns_hostname, ip=ns_ip)
    domain = domain.rstrip('.') + '.'
    
    # Test UDP
    try:
        query = dns.message.make_query(domain, dns.rdatatype.SOA)
        response = dns.query.udp(query, ns_ip, timeout=5)
        result.udp_works = True
        
        # Extract serial from SOA
        for rrset in list(response.answer) + list(response.authority):
            if rrset.rdtype == dns.rdatatype.SOA:
                result.serial = rrset[0].serial
                break
                
    except Exception as e:
        result.error = f"UDP error: {e}"
    
    # Test TCP
    try:
        query = dns.message.make_query(domain, dns.rdatatype.SOA)
        response = dns.query.tcp(query, ns_ip, timeout=5)
        result.tcp_works = True
        
        # If we didn't get serial from UDP, try from TCP
        if result.serial is None:
            for rrset in list(response.answer) + list(response.authority):
                if rrset.rdtype == dns.rdatatype.SOA:
                    result.serial = rrset[0].serial
                    break
                    
    except Exception as e:
        if result.error:
            result.error += f"; TCP error: {e}"
        else:
            result.error = f"TCP error: {e}"
    
    return result


def check_domain(domain: str, ip_version: str = 'both') -> bool:
    """
    Perform comprehensive DNS checks on a domain.
    ip_version: 'both', 'v4', or 'v6'
    Returns True if all checks pass, False otherwise.
    """
    domain = domain.lower().rstrip('.')
    print(f"\n{'='*60}")
    print(f"DNS Diagnostic Report for: {domain}")
    print(f"{'='*60}\n")
    
    all_ok = True
    
    # Step 1: Get glue records from parent zone
    print("[1] Querying parent zone for delegation (glue records)...")
    glue_ns, glue_ipv4, glue_ipv6 = get_glue_records(domain)

    if not glue_ns:
        print("  ERROR: Could not retrieve NS records from parent zone")
        print("  This may indicate the domain is not delegated or doesn't exist.\n")
        return False

    print(f"  Found {len(glue_ns)} nameserver(s) in parent zone delegation:")
    for ns in sorted(glue_ns):
        ipv4s = glue_ipv4.get(ns, set())
        ipv6s = glue_ipv6.get(ns, set())
        glue_parts = []
        if ipv4s:
            glue_parts.append(f"IPv4: {', '.join(sorted(ipv4s))}")
        if ipv6s:
            glue_parts.append(f"IPv6: {', '.join(sorted(ipv6s))}")
        if glue_parts:
            print(f"    - {ns} (glue: {' | '.join(glue_parts)})")
        else:
            print(f"    - {ns} (no glue record)")
    print()
    
    # Step 2: Resolve all nameserver IPs
    print("[2] Resolving nameserver IP addresses...")
    ns_ips = {}
    for ns in glue_ns:
        final_ipv4 = []
        final_ipv6 = []

        # Get IPs from glue or resolve
        if ns in glue_ipv4 or ns in glue_ipv6:
            glue_v4 = list(glue_ipv4.get(ns, set()))
            glue_v6 = list(glue_ipv6.get(ns, set()))
            if glue_v4 or glue_v6:
                final_ipv4 = glue_v4
                final_ipv6 = glue_v6
                parts = []
                if glue_v4:
                    parts.append(f"IPv4: {', '.join(glue_v4)}")
                if glue_v6:
                    parts.append(f"IPv6: {', '.join(glue_v6)}")
                print(f"  {ns}: {' | '.join(parts)} (from glue)")

        if not final_ipv4 and not final_ipv6:
            resolved_v4, resolved_v6 = resolve_hostname(ns)
            if resolved_v4 or resolved_v6:
                final_ipv4 = resolved_v4
                final_ipv6 = resolved_v6
                parts = []
                if resolved_v4:
                    parts.append(f"IPv4: {', '.join(resolved_v4)}")
                if resolved_v6:
                    parts.append(f"IPv6: {', '.join(resolved_v6)}")
                print(f"  {ns}: {' | '.join(parts)} (resolved)")
            else:
                print(f"  {ns}: FAILED TO RESOLVE")
                all_ok = False

        # Apply IP version filter
        if ip_version == 'v4':
            final_ipv6 = []
        elif ip_version == 'v6':
            final_ipv4 = []

        # Combine into single list for ns_ips
        all_ips = final_ipv4 + final_ipv6
        if all_ips:
            ns_ips[ns] = all_ips
    print()
    
    # Step 3: Query each authoritative NS for NS records and compare
    print("[3] Checking NS record consistency across nameservers...")
    auth_ns_sets = {}
    
    for ns, ips in ns_ips.items():
        if ips:
            auth_ns = get_authoritative_ns(domain, ips[0])
            auth_ns_sets[ns] = auth_ns
            print(f"  {ns} reports NS: {', '.join(sorted(auth_ns)) if auth_ns else 'QUERY FAILED'}")
    
    # Compare glue NS vs authoritative NS
    if auth_ns_sets:
        print("\n  Comparison:")
        any_auth_ns = next(iter(auth_ns_sets.values()), set())
        
        if glue_ns == any_auth_ns:
            print("  ✓ Glue records match authoritative NS records")
        else:
            all_ok = False
            only_in_glue = glue_ns - any_auth_ns
            only_in_auth = any_auth_ns - glue_ns
            if only_in_glue:
                print(f"  ✗ In parent zone but NOT in authoritative: {', '.join(sorted(only_in_glue))}")
            if only_in_auth:
                print(f"  ✗ In authoritative but NOT in parent zone: {', '.join(sorted(only_in_auth))}")
        
        # Check if all authoritative servers agree
        all_auth_sets = list(auth_ns_sets.values())
        if all_auth_sets and all(s == all_auth_sets[0] for s in all_auth_sets):
            print("  ✓ All authoritative nameservers report identical NS records")
        elif all_auth_sets:
            print("  ✗ WARNING: Authoritative nameservers report DIFFERENT NS records!")
            all_ok = False
    print()
    
    # Step 4: Test each nameserver (UDP, TCP, serial)
    print("[4] Testing nameserver connectivity and SOA serial consistency...")
    results = []
    
    for ns, ips in ns_ips.items():
        for ip in ips:
            result = test_nameserver(domain, ns, ip)
            results.append(result)
            
            status_parts = []
            if result.udp_works:
                status_parts.append("UDP:✓")
            else:
                status_parts.append("UDP:✗")
                all_ok = False
            
            if result.tcp_works:
                status_parts.append("TCP:✓")
            else:
                status_parts.append("TCP:✗")
                all_ok = False
            
            if result.serial is not None:
                status_parts.append(f"Serial:{result.serial}")
            else:
                status_parts.append("Serial:N/A")
            
            print(f"  {ns} ({ip}): {' | '.join(status_parts)}")
            if result.error and not (result.udp_works and result.tcp_works):
                print(f"    Error details: {result.error}")
    
    # Check serial consistency
    serials = [r.serial for r in results if r.serial is not None]
    if serials:
        print(f"\n  Serial number check:")
        if len(set(serials)) == 1:
            print(f"  ✓ All nameservers have consistent serial: {serials[0]}")
        else:
            print(f"  ✗ WARNING: Serial numbers are NOT consistent!")
            print(f"    Found serials: {', '.join(str(s) for s in sorted(set(serials)))}")
            all_ok = False
    else:
        print("\n  ✗ Could not retrieve SOA serial from any nameserver")
        all_ok = False
    
    # Summary
    print(f"\n{'='*60}")
    if all_ok:
        print("RESULT: All checks PASSED ✓")
    else:
        print("RESULT: Some checks FAILED ✗")
    print(f"{'='*60}\n")
    
    return all_ok


def main():
    parser = argparse.ArgumentParser(
        description='DNS Domain Diagnostic Tool - Check nameserver configuration and consistency',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s -v mydomain.org

This tool will:
  1. Query the parent zone for NS delegation (glue records)
  2. Query each authoritative nameserver for its NS records
  3. Compare glue records with authoritative NS records
  4. Test each nameserver over UDP and TCP
  5. Verify SOA serial number consistency
        """
    )
    parser.add_argument('domain', help='Domain name to check (e.g., example.com)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    ip_group = parser.add_mutually_exclusive_group()
    ip_group.add_argument('-4', '--ipv4-only', action='store_true', help='Check IPv4 addresses only')
    ip_group.add_argument('-6', '--ipv6-only', action='store_true', help='Check IPv6 addresses only')

    args = parser.parse_args()

    # Determine IP version preference
    if args.ipv4_only:
        ip_version = 'v4'
    elif args.ipv6_only:
        ip_version = 'v6'
    else:
        ip_version = 'both'
    
    # Basic domain validation
    domain = args.domain.strip().lower()
    if not domain or domain.startswith('.') or '..' in domain:
        print(f"Error: Invalid domain name: {args.domain}", file=sys.stderr)
        sys.exit(1)
    
    try:
        success = check_domain(domain, ip_version)
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
