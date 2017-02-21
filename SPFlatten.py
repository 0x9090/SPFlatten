#!/usr/bin/env python
import re, dns.resolver

#-----------------------------------------------------
# SPFlattener - Because who needs limits??
# Requires: dnspython
# Usage: edit the "root_domain" variable below and run
#-----------------------------------------------------
# To-do:
#     Confirm that SPF doesn't follow CNAMES (I don't think it does)
#     Should we consider Sender ID? ie spf2.0 (probably not)

#---------------------------------
root_domain = "google.com"
#---------------------------------

spf_ip_list = []
spf_nonflat_mechanisms = []

def main():
   global all_mechanism
   all_mechanism = ""
   flatten_spf(root_domain)

   dedupe_spf_ip_list = list(set(spf_ip_list))
   
   flat_spf = "v=spfv1"
   for ip in dedupe_spf_ip_list:
      if re.match(r'.*:.*', ip):
         flat_spf += (" ip6:" + ip)
      else:
         flat_spf += (" ip4:" + ip)

   for mechanism in spf_nonflat_mechanisms:
      flat_spf += mechanism

   flat_spf += all_mechanism

   print "\nFlattened SPF:\n----------------------\n", flat_spf


# Recursively flatten the SPF record for the specified domain
def flatten_spf(domain):
   print "--- Flattening:", domain, "---"
   try:
      txt_records = dns.resolver.query(domain, "TXT")
   except dns.exception.DNSException:
      print "No TXT records for:", domain
      return

   for record in txt_records:
      print "TXT record for:", domain, ":", str(record)
      fields = str(record)[1:-1].split(' ')

      if re.match(r'v=spf1', fields[0]):
         for field in fields:
            parse_mechanism(field, domain)


# Parse the given mechansim, and dispatch it accordintly
def parse_mechanism(mechanism, domain):
   if re.match(r'^a$', mechanism):
      convert_domain_to_ipv4(domain)
   elif re.match(r'^mx$', mechanism):
      convert_mx_to_ipv4(domain)
   elif re.match(r'^a:.*$', mechanism):
      match = re.match(r'^a:(.*)$', mechanism)
      convert_domain_to_ipv4(match.group(1))
   elif re.match(r'^ip4:.*$', mechanism):
      match = re.match(r'^ip4:(.*)$', mechanism)
      print "IPv4 address found for", domain, ":", match.group(1)
      spf_ip_list.append(match.group(1))
   elif re.match(r'^ip6:.*$', mechanism):
      match = re.match(r'^ip6:(.*)$', mechanism)
      print "IPv6 address found for", domain, ":", match.group(1)
      spf_ip_list.append(match.group(1))
   elif re.match(r'^ptr.*$', mechanism):
      print "PTR found for", domain, ":", mechanism
      spf_nonflat_mechanisms.append(mechanism)
   elif re.match(r'^exists:$', mechanism):
      print "Exists found for", domain, ":", mechanism
      spf_nonflat_mechanisms.append(mechanism)
   elif re.match(r'^redirect:$', mechanism):
      print "Redirect found for", domain, ":", mechanism
      spf_nonflat_mechanisms.append(mechanism)
   elif re.match(r'^exp:$', mechanism):
      print "EXP found for", domain, ":", mechanism
      spf_nonflat_mechanisms.append(mechanism)
   elif re.match(r'^.all$', mechanism):
      if domain == root_domain:
         match = re.match(r'^(.all)$', mechanism)
         print "All found for", domain, ":", match.group(1)
         all_mechanism = " " + str(match.group(1))
   elif re.match(r'^include:.*$', mechanism):
      match = re.match(r'^include:(.*)', mechanism)
      flatten_spf(match.group(1)) # recursion


# Convert A/AAAA records to IPs and adds them to the SPF master list
def convert_domain_to_ipv4(domain):
   a_records = []
   aaaa_records = []

   try:
      a_records = dns.resolver.query(domain, "A")
      for ip in a_records:
         print "A record for", domain, ":", str(ip)
         spf_ip_list.append(str(ip))
   except dns.exception.DNSException:
      pass

   try:
      aaaa_records = dns.resolver.query(domain, "AAAA")
      for ip in aaaa_records:
         print "A record for", domain, ":", str(ip)
         spf_ip_list.append(str(ip))
   except dns.exception.DNSException:
      pass


# Convert MX records to IPs and adds them to the SPF master list
def convert_mx_to_ipv4(domain):
   try:
      mx_records = dns.resolver.query(domain, "MX")
   except dns.exception.DNSException:
      return

   for record in mx_records:
      mx = str(record).split(' ')
      print "MX record found for ", domain, ": ", mx[1]
      convert_domain_to_ipv4(mx[1])      
      

if __name__ == "__main__": main()
