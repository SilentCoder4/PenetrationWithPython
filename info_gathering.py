#!/usr/bin/env python3
import argparse
import os
import socket
import whois
import dns.resolver
import shodan
import requests
from datetime import datetime

parser = argparse.ArgumentParser(description="Basic Information Gathering Tool", usage="python3 info-gathering.py -d DOMAIN [ -s IP ] -o filename.txt")
parser.add_argument("-d", "--domain", required=True, help="Domain name for footprinting")
parser.add_argument("-s", "--shodan", help="IP or query for Shodan search")
parser.add_argument("-o", "--output", help="Output filename")
args = parser.parse_args()

domain = args.domain.strip()
ip_query = args.shodan
output = args.output

result = ""

# WHOIS Section
result += "[+] WHOIS Information\n"
try:
    w = whois.whois(domain)
    name = w.get('domain_name') or w.get('domain')
    registrar = w.get('registrar')
    creation = w.get('creation_date') or w.get('created')
    if isinstance(creation, list):
        creation = creation[0]
    if isinstance(creation, datetime):
        creation = creation.isoformat()
    expiration = w.get('expiration_date') or w.get('expires')
    if isinstance(expiration, list):
        expiration = expiration[0]
    if isinstance(expiration, datetime):
        expiration = expiration.isoformat()
    registrant = w.get('registrant') or w.get('org')
    country = w.get('registrant_country') or w.get('country')

    result += f"Domain Name: {name}\nRegistrar: {registrar}\nCreation Date: {creation}\nExpiration Date: {expiration}\nRegistrant: {registrant}\nCountry: {country}\n"
except Exception as e:
    result += f"[-] WHOIS Error: {e}\n"

# DNS Section
result += "\n[+] DNS Records\n"
try:
    types = ["A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA"]
    for t in types:
        try:
            answers = dns.resolver.resolve(domain, t, lifetime=5)
            for r in answers:
                result += f"[*] {t} Record: {r.to_text()}\n"
        except:
            pass
except Exception as e:
    result += f"[-] DNS Error: {e}\n"

# GEOLOCATION Section
result += "\n[+] Geolocation Information\n"
try:
    ip = socket.gethostbyname(domain)
    result += f"Resolved IP: {ip}\n"
    geo = requests.get(f"https://geolocation-db.com/json/{ip}&position=true", timeout=6).json()
    result += f"Country: {geo.get('country_name')}\nState: {geo.get('state')}\nCity: {geo.get('city')}\nLatitude: {geo.get('latitude')}\nLongitude: {geo.get('longitude')}\n"
except Exception as e:
    result += f"[-] Geolocation Error: {e}\n"

# SHODAN Section
if ip_query:
    result += f"\n[+] Shodan Search for {ip_query}\n"
    try:
        key = os.environ.get("CNnZxGru644po9z9WDtWx8GMJqnTNoCX")
        if not key:
            result += "[-] SHODAN_API_KEY not set in environment\n"
        else:
            api = shodan.Shodan(key)
            try:
                data = api.search(ip_query)
                result += f"Results Found: {data.get('total', 0)}\n"
                for item in data.get('matches', []):
                    result += f"IP: {item.get('ip_str')}\nPort: {item.get('port')}\nData:\n{item.get('data')}\n{'-'*40}\n"
            except shodan.APIError:
                host = api.host(ip_query)
                result += f"IP: {host.get('ip_str')}\n"
                for s in host.get('data', []):
                    result += f"Port: {s.get('port')}\n{s.get('data')}\n{'-'*40}\n"
    except Exception as e:
        result += f"[-] Shodan Error: {e}\n"

print(result)

if output:
    try:
        with open(output, "w", encoding="utf-8") as f:
            f.write(result)
        print(f"[+] Results written to {output}")
    except Exception as e:
        print(f"[-] Failed to write output: {e}")