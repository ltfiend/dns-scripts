#!/usr/bin/env python3
"""Query a DNS server over DNS-over-TLS (DoT) and display certificate details."""

import argparse
import socket
import ssl
import struct
import sys
from datetime import datetime, timezone


def build_dns_query(domain: str, qtype: int = 1) -> bytes:
    """Build a simple DNS query packet."""
    import os
    tx_id = os.urandom(2)
    flags = b'\x01\x00'  # standard query, recursion desired
    counts = struct.pack('!HHHH', 1, 0, 0, 0)  # 1 question

    qname = b''
    for label in domain.rstrip('.').split('.'):
        qname += bytes([len(label)]) + label.encode()
    qname += b'\x00'

    question = qname + struct.pack('!HH', qtype, 1)  # type, class IN
    return tx_id + flags + counts + question


def parse_dns_response(data: bytes) -> list[str]:
    """Parse DNS response and return answer strings."""
    if len(data) < 12:
        return ['Invalid response']

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', data[:12])
    rcode = flags & 0x0F
    results = []
    results.append(f'  Transaction ID: 0x{tx_id:04x}')
    results.append(f'  Flags: 0x{flags:04x} (QR={int(bool(flags & 0x8000))}, AA={int(bool(flags & 0x0400))}, RD={int(bool(flags & 0x0100))}, RA={int(bool(flags & 0x0080))}, RCODE={rcode})')
    results.append(f'  Questions: {qdcount}, Answers: {ancount}, Authority: {nscount}, Additional: {arcount}')

    offset = 12
    # Skip questions
    for _ in range(qdcount):
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 0xC0:
                offset += 2
                break
            offset += 1 + length
        offset += 4  # qtype + qclass

    # Parse answers
    for i in range(ancount):
        if offset >= len(data):
            break
        # Parse name (handle compression)
        if data[offset] >= 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            offset += 1

        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10

        rdata_raw = data[offset:offset + rdlength]
        if rtype == 1 and rdlength == 4:  # A record
            ip = '.'.join(str(b) for b in rdata_raw)
            results.append(f'  Answer {i + 1}: A {ip} (TTL={ttl})')
        elif rtype == 28 and rdlength == 16:  # AAAA record
            import ipaddress
            ip6 = str(ipaddress.IPv6Address(rdata_raw))
            results.append(f'  Answer {i + 1}: AAAA {ip6} (TTL={ttl})')
        else:
            results.append(f'  Answer {i + 1}: type={rtype} rdlength={rdlength} (TTL={ttl})')
        offset += rdlength

    return results


def format_cert_details(cert: dict, der_cert: bytes) -> list[str]:
    """Format certificate details for display."""
    import hashlib
    lines = []

    subject = dict(x[0] for x in cert.get('subject', ()))
    issuer = dict(x[0] for x in cert.get('issuer', ()))

    lines.append(f'  Subject: {subject.get("commonName", "N/A")}')
    org = subject.get('organizationName')
    if org:
        lines.append(f'    Organization: {org}')

    lines.append(f'  Issuer:  {issuer.get("commonName", "N/A")}')
    org = issuer.get('organizationName')
    if org:
        lines.append(f'    Organization: {org}')

    lines.append(f'  Serial:  {cert.get("serialNumber", "N/A")}')
    lines.append(f'  Valid from: {cert.get("notBefore", "N/A")}')
    lines.append(f'  Valid to:   {cert.get("notAfter", "N/A")}')

    # Check expiry
    not_after = cert.get('notAfter')
    if not_after:
        try:
            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            remaining = expiry - datetime.now(timezone.utc)
            lines.append(f'  Days remaining: {remaining.days}')
        except ValueError:
            pass

    # SANs
    sans = cert.get('subjectAltName', ())
    if sans:
        san_list = [f'{t}:{v}' for t, v in sans]
        lines.append(f'  SANs: {", ".join(san_list)}')

    # Fingerprints
    lines.append(f'  SHA-256: {hashlib.sha256(der_cert).hexdigest()}')
    lines.append(f'  SHA-1:   {hashlib.sha1(der_cert).hexdigest()}')

    # TLS version and cipher
    return lines


def query_dot(server: str, domain: str, port: int = 853, qtype: int = 1) -> None:
    """Perform a DNS-over-TLS query and display results."""
    print(f'=== DNS-over-TLS Query ===')
    print(f'Server: {server}:{port}')
    print(f'Domain: {domain}')
    print(f'Type:   {"A" if qtype == 1 else "AAAA" if qtype == 28 else str(qtype)}')
    print()

    ctx = ssl.create_default_context()

    sock = socket.create_connection((server, port), timeout=10)
    with ctx.wrap_socket(sock, server_hostname=server) as tls_sock:
        # TLS info
        print('--- TLS Connection ---')
        print(f'  Protocol: {tls_sock.version()}')
        cipher = tls_sock.cipher()
        if cipher:
            print(f'  Cipher:   {cipher[0]}')
            print(f'  Bits:     {cipher[2]}')
        print()

        # Certificate details
        print('--- Certificate ---')
        cert = tls_sock.getpeercert()
        der_cert = tls_sock.getpeercert(binary_form=True)
        if cert and der_cert:
            for line in format_cert_details(cert, der_cert):
                print(line)
        else:
            print('  No certificate available')
        print()

        # Certificate chain
        try:
            chain = tls_sock.get_channel_binding()
        except Exception:
            pass

        # Send DNS query
        query = build_dns_query(domain, qtype)
        # DoT uses TCP length-prefixed messages
        tls_sock.sendall(struct.pack('!H', len(query)) + query)

        # Read response
        raw_len = tls_sock.recv(2)
        if len(raw_len) < 2:
            print('ERROR: No response received')
            return
        resp_len = struct.unpack('!H', raw_len)[0]
        response = b''
        while len(response) < resp_len:
            chunk = tls_sock.recv(resp_len - len(response))
            if not chunk:
                break
            response += chunk

        print('--- DNS Response ---')
        for line in parse_dns_response(response):
            print(line)
        print()


def main():
    parser = argparse.ArgumentParser(description='Query DNS over TLS and show certificate details')
    parser.add_argument('server', nargs='?', default='9.9.9.9', help='DoT server (default: 9.9.9.9)')
    parser.add_argument('domain', nargs='?', default='devries.tv', help='Domain to query (default: devries.tv)')
    parser.add_argument('-p', '--port', type=int, default=853, help='Port (default: 853)')
    parser.add_argument('-t', '--type', choices=['A', 'AAAA'], default='A', help='Query type (default: A)')
    args = parser.parse_args()

    qtype = 1 if args.type == 'A' else 28
    query_dot(args.server, args.domain, args.port, qtype)


if __name__ == '__main__':
    main()
