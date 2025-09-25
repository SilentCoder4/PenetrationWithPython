import whois
import dns.resolver
import shodan
import requests
import sys
import argparse

argparse = argparse.ArgumentParser(description="This is a basic information gathering tool.", usage="python3 info-gathering.py -d DOMAIN [ -s IP ]")
argparse.add_argument("-d", "--domain",help="Enter the domain name for footpringting.")
argparse.add_argument("-s", "--shodan",help="Enter the IP for shodan search.")

args = argparse.parse_args()
domain = args.domain
ip = args.shodan

# whois module
print("[+] Getting whois info...")
# using whois library, creating instance
py = whois.query(domain)
print("[+] whois info found.")
print("Name: {}".format(py.name))
print("Registrar: {}".format(py.registrar))
print("Creation Date: {}".format(py.creation_date))
print("Expiration date: {}". format(py.expiration_data))
print("Registrant: {}".format(py.registrant))
print("Registrant Country: {}".format(py.registrant_country))