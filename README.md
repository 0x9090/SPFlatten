SPFlatten
=========

Flatten SPF records

SPF has a limit as to how many DNS calls a SPF client can make before the protocol fails open. Many large email providers have a hard time coming under that 10 DNS call limit due to the complex nature of their email sending infrastructure. This script will recursively resolve the SPF records for a given domain, and flatten the INCLUDE, A, and MX records down to their respective IP4 or IP6 addresses. Only compatible with SPFv1.

Usage:
Edit the "root_domain" variable to be whatever domain you want the SPF record flattened for, and run the script. 

Output:
The program will echo out its progress, and give you a final Flattened SPF record - which should be mostly IP4 and IP6 addresses.
