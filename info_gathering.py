import socket

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
try:

    py = whois.whois(domain)
    print("[+] whois info found.")

    print("Name: {}".format(py.get('domain_name')))
    print("Registrar: {}".format(py.get('registrar')))
    print("Creation Date: {}".format(py.get('creation_date')))
    print("Expiration date: {}". format(py.get('expiration_data')))
    print("Registrant: {}".format(py.get('registrant')))
    print("Registrant Country: {}".format(py.get('registrant_country')))
except: pass


#DNS Module
print("[*] Getting DNS Info..")

try:
    for a in dns.resolver.resolve(domain, 'A'):
        print("[*] A Record: {}",format(a.to.text()))
    for ns in dns.resolver.resolve(domain, 'NS'):
        print("[*] NS Record: {}",format(ns.to.text()))
    for mx in dns.resolver.resolve(domain, 'MX'):
        print("[*] MX Record: {}",format(mx.to.text()))
    for txt in dns.resolver.resolve(domain, 'TXT'):
        print("[*] TXT Record: {}",format(txt.to.text()))
except:
    pass
# for post upgrade

#geolocation
print("[+] Getting geolocation info..")

#implementing geolocation
try:
    response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    print("[+] Country: {}".format(response['country_name']))
    print("[+] Lattitude: {}".format(response['lattitude']))
    print("[+] Longitude: {}".format(response['longitude']))
    print("[+] City: {}".format(response['city']))
    print("[+] State: {}".format(response['state']))
except:
    pass

