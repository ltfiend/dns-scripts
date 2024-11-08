#!/usr/bin/python3

# Get IPs for all running ECSs in a cluster and add / remove them from the domains NSSet

import boto3
import dns.tsigkeyring
import dns.update
import dns.query
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdataset
import dns.message
import configparser
import json
import os

confFile = os.path.expanduser("~") + "/.nsset-maintainer.conf"

config = configparser.ConfigParser()
config.read_file(open(confFile))

TSIGKeyName = config["TSIG"]["name"]
TSIGKey = config["TSIG"]["key"]

keyring = dns.tsigkeyring.from_text({TSIGKeyName: TSIGKey})

debug = 0
output = 1
zone = config["CONFIG"]["zone"]
cluster = config["CONFIG"]["cluster"]
auth_server = config["CONFIG"]["auth_server"]

# nameservers that shouldn't be removed
staticnslist = json.loads(config.get("CONFIG", "staticnslist"))

ecsnslist = []

ecs = boto3.client("ecs", region_name="us-east-1")
ec2 = boto3.client("ec2", region_name="us-east-1")


def makeNSSet(nslist):
    newNSSet = dns.rdataset.from_text(dns.rdataclass.IN, dns.rdatatype.NS, 10800)
    for ns in nslist:
        if not (ns.endswith(".")):
            ns = ns + "."
        newNSrr = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, ns)
        newNSSet.add(newNSrr)
    return newNSSet


def sendOutput():
    print("*****")
    print("existing")
    print(existingNS)
    print("static")
    print(staticNS)
    print("ecs")
    print(ecsNS)  #  ECS + Static
    print("remove")
    print(removeNS)
    print("add")
    print(addNS)  #  ECS + Static
    print("missing")
    print(missingNS)  #  ECS + Static
    print("*****")


# Process all the tasks in the cluster
tasks = ecs.list_tasks(cluster=cluster)
if debug >= 2:
    print(tasks)
if len(tasks["taskArns"]) > 0:
    print("Processing tasks: ", len(tasks["taskArns"]))
    taskDetails = ecs.describe_tasks(cluster=cluster, tasks=tasks["taskArns"])
    for taskItem in taskDetails["tasks"]:
        if debug >= 3:
            print(taskItem)
        interfaceId = taskItem["attachments"][0]["details"][1]["value"]
        interface = ec2.describe_network_interfaces(NetworkInterfaceIds=[interfaceId])
        if debug >= 1:
            print(interfaceId)
            print(interface["NetworkInterfaces"][0]["Association"]["PublicDnsName"])
        ecsnslist.append(
            interface["NetworkInterfaces"][0]["Association"]["PublicDnsName"]
        )

# Get existing NSset from the auth server
qname = dns.name.from_text(zone)
query = dns.message.make_query(qname, dns.rdatatype.NS)
nsset = dns.query.udp(query, auth_server)
existingNS = nsset.answer[0].to_rdataset()

ecsNS = makeNSSet(ecsnslist)
staticNS = makeNSSet(staticnslist)

# Figure out what records need to be removed and added
removeNS = existingNS
removeNS = removeNS.difference(ecsNS)
removeNS = removeNS.difference(staticNS)
addNS = ecsNS.difference(existingNS)
missingNS = staticNS.difference(existingNS)

addNS = addNS.union(missingNS)

# Debugging stuff, delete later
if output >= 1:
    sendOutput()

# Add any new entries.
if len(addNS) >= 1:
    update = dns.update.UpdateMessage(zone, keyring=keyring)
    if len(addNS) > 0:
        for a in addNS:
            print(a.to_text())
            update.add(zone, 10800, "NS", a.to_text())
    response = dns.query.tcp(update, auth_server)
    if debug >= 1:
        print(update)
        print(response)

# Remove any unneeded entries
if len(removeNS) >= 1:
    update = dns.update.UpdateMessage(zone, keyring=keyring)
    for r in removeNS:
        update.delete(zone, "NS", r.to_text())
    response = dns.query.tcp(update, auth_server)
    if debug >= 1:
        print(update)
        print(response)
