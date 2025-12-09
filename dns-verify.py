#!/usr/bin/env python3

import argparse
import sys
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.name
from collections import defaultdict

def get_authoritative_nameservers(domain):
    """Find the authoritative nameservers for a domain"""
    nameservers = []

    try:
        # Use a public DNS resolver for initial query
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']

        # Query for NS records
        answers = resolver.resolve(domain, 'NS')

        for rdata in answers:
            ns_name = str(rdata.target).rstrip('.')
            nameservers.append(ns_name)

    except dns.resolver.NXDOMAIN:
        print(f"Error: Domain {domain} does not exist (NXDOMAIN)")
        return None
    except dns.resolver.NoAnswer:
        print(f"Error: No nameservers found for {domain}")
        return None
    except dns.resolver.Timeout:
        print(f"Error: Timeout querying nameservers for {domain}")
        return None
    except Exception as e:
        print(f"Error querying nameservers: {str(e)}")
        return None

    return nameservers

def resolve_nameserver_ip(nameserver):
    """Resolve a nameserver hostname to its IP address"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']

        answers = resolver.resolve(nameserver, 'A')
        return str(answers[0])
    except:
        try:
            # Try AAAA if A fails
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']

            answers = resolver.resolve(nameserver, 'AAAA')
            return str(answers[0])
        except:
            return None

def query_soa(nameserver_ip, domain):
    """Query SOA record from a specific nameserver"""
    try:
        # Create SOA query
        query_msg = dns.message.make_query(domain, dns.rdatatype.SOA)

        # Send query to specific nameserver
        response = dns.query.udp(query_msg, nameserver_ip, timeout=10)

        if response.rcode() != dns.rcode.NOERROR:
            return None, f"Response code: {dns.rcode.to_text(response.rcode())}"

        # Extract SOA record from answer section
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                for rdata in rrset:
                    return rdata, None

        # Check authority section if not in answer
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.SOA:
                for rdata in rrset:
                    return rdata, None

        return None, "No SOA record in response"

    except dns.exception.Timeout:
        return None, "Timeout"
    except Exception as e:
        return None, str(e)

def format_soa(soa):
    """Format SOA record for display"""
    return f"""  Primary NS: {soa.mname}
  Responsible: {soa.rname}
  Serial: {soa.serial}
  Refresh: {soa.refresh}
  Retry: {soa.retry}
  Expire: {soa.expire}
  Minimum TTL: {soa.minimum}"""

def verify_domain(domain, verbose=False):
    """Main verification function"""
    print(f"Verifying DNS for domain: {domain}")
    print("=" * 70)

    # Step 1: Get authoritative nameservers
    print("\n[Step 1] Finding authoritative nameservers...")
    nameservers = get_authoritative_nameservers(domain)

    if not nameservers:
        return False

    print(f"Found {len(nameservers)} nameserver(s):")
    for ns in nameservers:
        print(f"  - {ns}")

    # Step 2: Resolve nameserver IPs
    print("\n[Step 2] Resolving nameserver IP addresses...")
    ns_ips = {}
    for ns in nameservers:
        ip = resolve_nameserver_ip(ns)
        if ip:
            ns_ips[ns] = ip
            print(f"  {ns} -> {ip}")
        else:
            print(f"  {ns} -> Failed to resolve")

    if not ns_ips:
        print("\nError: Could not resolve any nameserver IPs")
        return False

    # Step 3: Query SOA from each nameserver
    print("\n[Step 3] Querying SOA records from each nameserver...")
    soa_records = {}
    errors = {}

    for ns, ip in ns_ips.items():
        print(f"\nQuerying {ns} ({ip})...")
        soa, error = query_soa(ip, domain)

        if soa:
            soa_records[ns] = soa
            print(f"✓ Response received")
            if verbose:
                print(format_soa(soa))
        else:
            errors[ns] = error
            print(f"✗ Failed: {error}")

    if not soa_records:
        print("\n" + "=" * 70)
        print("RESULT: FAILED - No nameservers responded with SOA records")
        return False

    # Step 4: Compare SOA records
    print("\n[Step 4] Comparing SOA records...")
    print("-" * 70)

    # Group nameservers by SOA serial
    serial_groups = defaultdict(list)
    for ns, soa in soa_records.items():
        serial_groups[soa.serial].append((ns, soa))

    all_in_sync = len(serial_groups) == 1

    if all_in_sync:
        print("✓ All SOA records are IN SYNC")
        serial = list(serial_groups.keys())[0]
        print(f"\nSerial number: {serial}")

        # Show detailed SOA info
        example_soa = list(soa_records.values())[0]
        print(format_soa(example_soa))

    else:
        print("✗ SOA records are OUT OF SYNC")
        print(f"\nFound {len(serial_groups)} different serial numbers:\n")

        for serial in sorted(serial_groups.keys(), reverse=True):
            ns_list = serial_groups[serial]
            print(f"Serial {serial}:")
            for ns, soa in ns_list:
                print(f"  - {ns}")
            if verbose:
                print(format_soa(ns_list[0][1]))
            print()

    # Summary
    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)
    print(f"Total nameservers found: {len(nameservers)}")
    print(f"Nameservers responding: {len(soa_records)}")
    print(f"Nameservers with errors: {len(errors)}")

    if errors:
        print("\nNameservers with errors:")
        for ns, error in errors.items():
            print(f"  - {ns}: {error}")

    print(f"\nSOA synchronization: {'✓ IN SYNC' if all_in_sync else '✗ OUT OF SYNC'}")

    # Overall result
    overall_success = all_in_sync and len(errors) == 0

    print("\n" + "=" * 70)
    if overall_success:
        print("RESULT: ✓ PASSED - All nameservers responding and in sync")
    else:
        print("RESULT: ✗ FAILED - Issues detected")
    print("=" * 70)

    return overall_success

def main():
    parser = argparse.ArgumentParser(
        description="DNS verification tool - finds authoritative nameservers and verifies SOA synchronization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s google.com --verbose
  %(prog)s cloudflare.com -v

This tool will:
  1. Find all authoritative nameservers for the domain
  2. Resolve nameserver IP addresses
  3. Query SOA record from each nameserver
  4. Verify all nameservers respond correctly
  5. Check that all SOA records are synchronized
        """
    )

    parser.add_argument('domain',
                       help='Domain name to verify')

    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Verbose output - show detailed SOA information')

    args = parser.parse_args()

    try:
        # Remove any protocol prefix and trailing slashes
        domain = args.domain.replace('https://', '').replace('http://', '').rstrip('/')

        # Remove trailing dot if present
        domain = domain.rstrip('.')

        success = verify_domain(domain, args.verbose)

        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
