#!/usr/bin/env python3

import argparse
import sys
import dns.resolver
import dns.query
import dns.message
import dns.rdatatype
import dns.edns

def query_all_rr_types(server, fqdn, quiet=False):
    """Query all RR types for a given FQDN from a specific DNS server"""
    
    # Get all available RR types
    rr_types = []
    for attr_name in dir(dns.rdatatype):
        if not attr_name.startswith('_') and attr_name.isupper():
            try:
                rr_type = getattr(dns.rdatatype, attr_name)
                if isinstance(rr_type, int) and rr_type > 0:
                    rr_types.append((attr_name, rr_type))
            except:
                continue
    
    # Sort by RR type number
    rr_types.sort(key=lambda x: x[1])
    
    if not quiet:
        print(f"Querying {fqdn} from server {server}")
        print("=" * 50)
    
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server]
    resolver.timeout = 5
    resolver.lifetime = 10
    
    found_records = False
    
    for rr_name, rr_type in rr_types:
        try:
            answer = resolver.resolve(fqdn, rr_type)
            found_records = True
            if quiet:
                print(f"{rr_name}:")
                for rdata in answer:
                    print(f"  {rdata}")
            else:
                print(f"{rr_name} ({rr_type}):")
                for rdata in answer:
                    print(f"  {rdata}")
        except dns.resolver.NoAnswer:
            if not quiet:
                print(f"{rr_name} ({rr_type}): No RR")
        except dns.resolver.NXDOMAIN:
            if not quiet:
                print(f"{rr_name} ({rr_type}): NXDOMAIN")
        except dns.resolver.Timeout:
            if not quiet:
                print(f"{rr_name} ({rr_type}): Timeout")
        except Exception as e:
            if not quiet:
                print(f"{rr_name} ({rr_type}): Error - {str(e)}")
    
    if quiet and not found_records:
        print("No resource records found")

def edns_test(server, fqdn, quiet=False):
    """Test EDNS versions 0-100 with A record queries"""
    
    if not quiet:
        print(f"EDNS Testing for A record: {fqdn} from server {server}")
        print("=" * 50)
    
    successful_queries = []
    
    for edns_version in range(101):  # 0 to 100
        try:
            # Create a query message
            query_msg = dns.message.make_query(fqdn, dns.rdatatype.A)
            
            # Add EDNS option
            if edns_version == 0:
                # Standard EDNS0
                query_msg.use_edns(edns=0, ednsflags=0, payload=4096)
            else:
                # For versions > 0, we need to manually set the version
                query_msg.use_edns(edns=edns_version, ednsflags=0, payload=4096)
            
            # Send the query
            response = dns.query.udp(query_msg, server, timeout=5)
            
            # Check response
            if response.rcode() == dns.rcode.NOERROR:
                if len(response.answer) > 0:
                    if quiet:
                        successful_queries.append((edns_version, response.answer))
                    else:
                        print(f"EDNS {edns_version}: SUCCESS - Got answer:")
                        for rrset in response.answer:
                            for rr in rrset:
                                print(f"  {rr}")
                else:
                    if not quiet:
                        print(f"EDNS {edns_version}: SUCCESS - No answer section")
            elif response.rcode() == dns.rcode.FORMERR:
                if not quiet:
                    print(f"EDNS {edns_version}: FORMERR (Format Error)")
            elif response.rcode() == dns.rcode.NXDOMAIN:
                if not quiet:
                    print(f"EDNS {edns_version}: NXDOMAIN")
            elif response.rcode() == dns.rcode.SERVFAIL:
                if not quiet:
                    print(f"EDNS {edns_version}: SERVFAIL")
            else:
                if not quiet:
                    print(f"EDNS {edns_version}: Response code {dns.rcode.to_text(response.rcode())}")
                    
        except dns.exception.Timeout:
            if not quiet:
                print(f"EDNS {edns_version}: Timeout")
        except dns.query.BadResponse:
            if not quiet:
                print(f"EDNS {edns_version}: Bad Response")
        except Exception as e:
            if not quiet:
                print(f"EDNS {edns_version}: Error - {str(e)}")
    
    # In quiet mode, only print successful queries with answers
    if quiet:
        if successful_queries:
            for edns_version, answer in successful_queries:
                print(f"EDNS {edns_version}:")
                for rrset in answer:
                    for rr in rrset:
                        print(f"  {rr}")
        else:
            print("No successful EDNS queries with answers")

def main():
    parser = argparse.ArgumentParser(
        description="DNS query tool for testing RR types and EDNS versions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -s 8.8.8.8 -f google.com
  %(prog)s -s 1.1.1.1 -f example.com --edns-test
  %(prog)s --server 8.8.8.8 --fqdn cloudflare.com --edns-test --quiet
  %(prog)s -s 8.8.8.8 -f google.com -q
        """
    )
    
    parser.add_argument('-s', '--server', 
                       required=True,
                       help='DNS server to query')
    
    parser.add_argument('-f', '--fqdn',
                       required=True, 
                       help='Fully Qualified Domain Name to query')
    
    parser.add_argument('--edns-test',
                       action='store_true',
                       help='Perform EDNS version testing (0-100) with A record queries')
    
    parser.add_argument('-q', '--quiet',
                       action='store_true',
                       help='Quiet mode - only print existing resource records')
    
    args = parser.parse_args()
    
    try:
        if args.edns_test:
            edns_test(args.server, args.fqdn, args.quiet)
        else:
            query_all_rr_types(args.server, args.fqdn, args.quiet)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
