#!/usr/bin/env python3

import argparse
import logging
import re
import dns.resolver

# -----------------------------------------------------
# https://github.com/0x9090/SPFlatten
# SPFlattener - Because who needs limits??
# Requires: dnspython
# Usage: SPFlatten.py yourdmomain.com and-optional-others.net etc.org
# -----------------------------------------------------
# To-do:
#     Confirm that SPF doesn't follow CNAMES (I don't think it does)
#     Should we consider Sender ID? ie spf2.0 (probably not)

# ---------------------------------

logger = logging.getLogger('spflat')

class Flattener:
    def __init__(self, domain=None, root_domain=None):
        self.all_mechanism = ''
        self.spf_nonflat_mechanisms = []
        self.spf_ip_list = []
        self.domain = domain
        self.root_domain = root_domain

    def dump(self):
        '''
        Deduplicate (possibly nested) records 
        '''
        dedupe_spf_ip_list = list(set(self.spf_ip_list))
        flat_spf = "v=spf1"
        for ip in dedupe_spf_ip_list:
            if re.match(r'.*:.*', ip):
                flat_spf += (" ip6:" + ip)
            else:
                flat_spf += (" ip4:" + ip)

        for mechanism in self.spf_nonflat_mechanisms:
            flat_spf += " " + mechanism
        flat_spf += self.all_mechanism

        logger.info("%s flattened SPF", self.domain)
        print(flat_spf)

    def flatten_domain(self):
        logger.debug("Flattening: %s", self.domain)
        try:
            txt_records = dns.resolver.resolve(self.domain, "TXT")
        except dns.exception.DNSException:
            logger.debug("No TXT records for: %s", self.domain)
            return

        for record in txt_records:
            logger.debug("TXT record for: %s:%s", self.domain, str(record))
            joinrecord = ''.join([x for x in str(record).split('"') if x.strip()])
            fields = joinrecord.split(' ')

            if re.match(r'v=spf1', fields[0]):
                self.flatten_record(joinrecord)

    # Recursively flatten the SPF record for the specified domain
    def flatten_record(self, record):
        for field in record.split(' '):
            self.parse_mechanism(field)

    # Parse the given mechansim, and dispatch it accordintly
    def parse_mechanism(self, mechanism):
        if re.match(r'^a$', mechanism):
            self.spf_ip_list.extend(Flattener.convert_domain_to_ipv4(self.domain))
        elif re.match(r'^mx$', mechanism):
            logger.debug("MX found for %s:%s", self.domain, mechanism)
            self.spf_ip_list.extend(Flattener.convert_mx_to_ipv4(self.domain))
        elif re.match(r'^a:.*$', mechanism):
            match = re.match(r'^a:(.*)$', mechanism)
            self.spf_ip_list.extend(Flattener.convert_domain_to_ipv4(match.group(1)))
        elif re.match(r'^ip4:.*$', mechanism):
            match = re.match(r'^ip4:(.*)$', mechanism)
            logger.debug("IPv4 address found for %s:%s", self.domain, match.group(1))
            self.spf_ip_list.append(match.group(1))
        elif re.match(r'^ip6:.*$', mechanism):
            match = re.match(r'^ip6:(.*)$', mechanism)
            logger.debug("IPv6 address found for %s:%s", self.domain, match.group(1))
            self.spf_ip_list.append(match.group(1))
        elif re.match(r'^ptr.*$', mechanism):
            logger.debug("PTR found for %s:%s", self.domain, mechanism)
            self.spf_nonflat_mechanisms.append(mechanism)
        elif re.match(r'^exists:$', mechanism):
            logger.debug("Exists found for %s:%s", self.domain, mechanism)
            self.spf_nonflat_mechanisms.append(mechanism)
        elif re.match(r'^redirect(?:[=:]) ?(.*)$', mechanism):
            logger.debug("Redirect found for %s:%s", self.domain, mechanism)
            match = re.match(r'^redirect(?:[=:]) ?(.*)', mechanism)
            newdom = Flattener(match.group(1), self.root_domain)
            newdom.flatten_domain()  # recursion
            self.spf_nonflat_mechanisms.extend(newdom.spf_nonflat_mechanisms)
            self.spf_ip_list.extend(newdom.spf_ip_list)
            #
            # self.spf_nonflat_mechanisms.append(mechanism)
            # flatten_domain(re.match(r'^redirect(?:[\=\:])\ ?(.*)$', mechanism).group(1))
        elif re.match(r'^exp:$', mechanism):
            logger.debug("EXP found for %s:%s", self.domain, mechanism)
            self.spf_nonflat_mechanisms.append(mechanism)
        elif re.match(r'^.all$', mechanism):
            if self.domain == self.root_domain or self.all_mechanism == '':
                match = re.match(r'^(.all)$', mechanism)
                logger.debug("All found for %s:%s", self.domain, match.group(1))
                self.all_mechanism = " " + str(match.group(1))
        elif re.match(r'^include:.*$', mechanism):
            match = re.match(r'^include:(.*)', mechanism)
            newdom = Flattener(match.group(1), self.root_domain)
            newdom.flatten_domain()  # recursion
            self.spf_nonflat_mechanisms.extend(newdom.spf_nonflat_mechanisms)
            self.spf_ip_list.extend(newdom.spf_ip_list)


    # Convert A/AAAA records to IPs and adds them to the SPF master list
    @staticmethod
    def convert_domain_to_ipv4(domain):
        if not domain:
            logger.warning("Can't resolve \"a\" or \"mx\" mechanism without specifying a domain. Results will be partial")
            return []

        spf_ip_list = []
        try:
            a_records = dns.resolver.resolve(domain, "A")
            for ip in a_records:
                logger.debug("A record for %s:%s", domain, str(ip))
                spf_ip_list.append(str(ip))
        except dns.exception.DNSException:
            pass

        try:
            aaaa_records = dns.resolver.resolve(domain, "AAAA")
            for ip in aaaa_records:
                logger.debug("A record for %s:%s", domain, str(ip))
                spf_ip_list.append(str(ip))
        except dns.exception.DNSException:
            pass

        return spf_ip_list

    # Convert MX records to IPs and adds them to the SPF master list
    @staticmethod
    def convert_mx_to_ipv4(domain):
        try:
            mx_records = dns.resolver.resolve(domain, "MX")
        except dns.exception.DNSException:
            import pdb
            pdb.set_trace()
            return []

        spf_ip_list = []
        for record in mx_records:
            mx = str(record).split(' ')
            logger.debug("MX record found for %s:%s ", domain, mx[1])
            spf_ip_list.extend(Flattener.convert_domain_to_ipv4(mx[1]))

        return spf_ip_list


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Flatten SPF records",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='foo')
    parser.add_argument('values', nargs='+',
                        help='One or more domains from which SPF will be fetched and flattened.')
    parser.add_argument('-i', '--inlined', action='store_true',
                        help='If set, the argument is expect to be an inlined SPF records.')
    parser.add_argument('-d', '--domain',
                        help='With -i, specify the domain in order to resolve "a" or "mx" records.')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='More verbose')

    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels)-1, args.verbose)]
    logging.basicConfig(level=level)

    if args.inlined:
        f = Flattener(args.domain)
        f.flatten_record(args.values[0])
        f.dump()
    else:
        for dom in args.values:
            f = Flattener(dom)
            f.flatten_domain()
            f.dump()
