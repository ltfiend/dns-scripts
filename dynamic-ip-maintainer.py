#!/usr/bin/python3

# Get IPs for all running ECSs in a cluster and add / remove them from the domains NSSet

import dns.tsigkeyring
import dns.update
import dns.query
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdataset
import dns.message
import dns.resolver
import configparser
import os
import requests

requests.packages.urllib3.util.connection.HAS_IPV6 = False

confFile = os.path.expanduser("~") + "/.nsset-maintainer.conf"

config = configparser.ConfigParser()
config.read_file(open(confFile))

TSIGKeyName = config["TSIG"]["name"]
TSIGKey = config["TSIG"]["key"]

keyring = dns.tsigkeyring.from_text({TSIGKeyName: TSIGKey})

debug = 2
output = 1
zone = config["CONFIG"]["zone"]
auth_server = config["CONFIG"]["auth_server"]

IPqname = "o-o.myaddr.l.google.com."
qname = "example.com."
NSName = "ns1.example.com"


def get_ip_address(domain, rrtype, server):
    try:
        # Query for A arecords
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server]
        # answers = dns.resolver.resolve(domain, "TXT")
        answers = resolver.resolve(domain, rrtype)
        for rdata in answers:
            # print(rdata.to_text())
            return rdata.to_text()
    except dns.resolver.NoAnswer:
        print(f"No A records found for {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"{domain} does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")


# Get existing NSset from the auth server
googledns = get_ip_address("ns1.google.com", "A", "8.8.8.8")
#CurrentIP = get_ip_address(IPqname, "TXT", googledns)
#CurrentIP = CurrentIP.replace('"', "")
CurrentIP = requests.get('http://ifconfig.me')
# print("Current -", CurrentIP.text)
NSip = get_ip_address(NSName, "A", "8.8.8.8")
# For testing - forces DNSip to be an old one, triggering an update
# DNSip = get_ip_address("test34b.devries.tv", "A", NSip)
DNSip = get_ip_address(qname, "A", NSip)
if debug >= 2:
    print(CurrentIP.text)
    print(DNSip)

if DNSip == CurrentIP.text:
    if debug >= 1: print("No Change Required")

if DNSip != CurrentIP.text:
    print("IP has changed, Updating DNS. Old:", DNSip, "New:", CurrentIP)
    update = dns.update.UpdateMessage(zone, keyring=keyring)
    update.delete(qname)
    update.add(qname, 300, "A", CurrentIP.text)
    response = dns.query.tcp(update, auth_server)
    if debug >= 2:
        print(update)
        print(response)
