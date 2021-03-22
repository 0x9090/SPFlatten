#!/usr/bin/env python3

import dns.resolver
import re
import sys

# -----------------------------------------------------
# SPFlattener - Because who needs limits??
# Requires: dnspython
# Usage: SPFlatten.py yourdmomain.com and-optional-others.net etc.org
# -----------------------------------------------------
# To-do:
#     Confirm that SPF doesn't follow CNAMES (I don't think it does)
#     Should we consider Sender ID? ie spf2.0 (probably not)

# ---------------------------------
if len(sys.argv) <= 1:
    sys.exit(1)

isDebug = 0
root_domain = ''
all_mechanism = ''
spf_nonflat_mechanisms = []
spf_ip_list = []

root_domains = sys.argv[1:]


def debug(*args, **kwargs):
    global isDebug
    if isDebug:
        print(*args, **kwargs)


# ---------------------------------

def main():
    global all_mechanism
    global root_domain
    global spf_nonflat_mechanisms
    global spf_ip_list

    for root_domain in root_domains:
        all_mechanism = ''
        spf_nonflat_mechanisms = []
        spf_ip_list = []

        flatten_spf(root_domain)

        dedupe_spf_ip_list = list(set(spf_ip_list))

        flat_spf = "v=spf1"
        for ip in dedupe_spf_ip_list:
            if re.match(r'.*:.*', ip):
                flat_spf += (" ip6:" + ip)
            else:
                flat_spf += (" ip4:" + ip)

        for mechanism in spf_nonflat_mechanisms:
            flat_spf += " " + mechanism

        flat_spf += all_mechanism

        print("#### Flattened SPF for %s ####\n----------------------\n%s\n" % (root_domain, flat_spf))


# Recursively flatten the SPF record for the specified domain
def flatten_spf(domain):
    global all_mechanism

    debug("--- Flattening:", domain, "---")
    try:
        txt_records = dns.resolver.query(domain, "TXT")
    except dns.exception.DNSException:
        debug("No TXT records for:", domain)
        return

    for record in txt_records:
        debug("TXT record for:", domain, ":", str(record))
        joinrecord = ''.join([x for x in str(record).split('"') if x.strip()])
        fields = joinrecord.split(' ')

        if re.match(r'v=spf1', fields[0]):
            for field in fields:
                parse_mechanism(field, domain)


# Parse the given mechansim, and dispatch it accordintly
def parse_mechanism(mechanism, domain):
    global all_mechanism

    if re.match(r'^a$', mechanism):
        convert_domain_to_ipv4(domain)
    elif re.match(r'^mx$', mechanism):
        debug("MX found for", root_domain, ":", mechanism)
        convert_mx_to_ipv4(root_domain)
    elif re.match(r'^a:.*$', mechanism):
        match = re.match(r'^a:(.*)$', mechanism)
        convert_domain_to_ipv4(match.group(1))
    elif re.match(r'^ip4:.*$', mechanism):
        match = re.match(r'^ip4:(.*)$', mechanism)
        debug("IPv4 address found for", domain, ":", match.group(1))
        spf_ip_list.append(match.group(1))
    elif re.match(r'^ip6:.*$', mechanism):
        match = re.match(r'^ip6:(.*)$', mechanism)
        debug("IPv6 address found for", domain, ":", match.group(1))
        spf_ip_list.append(match.group(1))
    elif re.match(r'^ptr.*$', mechanism):
        debug("PTR found for", domain, ":", mechanism)
        spf_nonflat_mechanisms.append(mechanism)
    elif re.match(r'^exists:$', mechanism):
        debug("Exists found for", domain, ":", mechanism)
        spf_nonflat_mechanisms.append(mechanism)
    elif re.match(r'^redirect(?:[=:]) ?(.*)$', mechanism):
        debug("Redirect found for", domain, ":", mechanism)
        match = re.match(r'^redirect(?:[=:]) ?(.*)', mechanism)
        flatten_spf(match.group(1))  # recursion
        #
        # spf_nonflat_mechanisms.append(mechanism)
        # flatten_spf(re.match(r'^redirect(?:[\=\:])\ ?(.*)$', mechanism).group(1))
    elif re.match(r'^exp:$', mechanism):
        debug("EXP found for", domain, ":", mechanism)
        spf_nonflat_mechanisms.append(mechanism)
    elif re.match(r'^.all$', mechanism):
        if domain == root_domain or all_mechanism == '':
            match = re.match(r'^(.all)$', mechanism)
            debug("All found for", domain, ":", match.group(1))
            all_mechanism = " " + str(match.group(1))
    elif re.match(r'^include:.*$', mechanism):
        match = re.match(r'^include:(.*)', mechanism)
        flatten_spf(match.group(1))  # recursion


# Convert A/AAAA records to IPs and adds them to the SPF master list
def convert_domain_to_ipv4(domain):
    try:
        a_records = dns.resolver.query(domain, "A")
        for ip in a_records:
            debug("A record for", domain, ":", str(ip))
            spf_ip_list.append(str(ip))
    except dns.exception.DNSException:
        pass

    try:
        aaaa_records = dns.resolver.query(domain, "AAAA")
        for ip in aaaa_records:
            debug("A record for", domain, ":", str(ip))
            spf_ip_list.append(str(ip))
    except dns.exception.DNSException:
        pass


# Convert MX records to IPs and adds them to the SPF master list
def convert_mx_to_ipv4(domain):
    try:
        mx_records = dns.resolver.query(domain, "MX")
    except dns.exception.DNSException:
        import pdb
        pdb.set_trace()
        return

    for record in mx_records:
        mx = str(record).split(' ')
        debug("MX record found for ", domain, ": ", mx[1])
        convert_domain_to_ipv4(mx[1])


if __name__ == "__main__":
    main()
