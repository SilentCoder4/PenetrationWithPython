import socket
import whois
import dns.resolver
import shodan
import requests
import argparse

argparse = argparse.ArgumentParser(description="This is a basic information gathering tool.", usage="python3 info-gathering.py -d DOMAIN [ -s IP ]")
argparse.add_argument("-d", "--domain",help="Enter the domain name for footpringting.")
argparse.add_argument("-s", "--shodan",help="Enter the IP for shodan search.")
argparse.add_argument("-o", "--output",help="Enter the filename.")

args = argparse.parse_args()
domain = args.domain
ip = args.shodan
output = args.output

# whois module
print("[+] Getting whois info...")
whois_result = ''
# using whois library, creating instance
try:

    py = whois.whois(domain)
    print("[+] whois info found.")

    whois_result += "Name: {}".format(py.get('domain_name')) + '\n'
    whois_result += "Registrar: {}".format(py.get('registrar')) + '\n'
    whois_result += "Creation Date: {}".format(py.get('creation_date')) + '\n'
    whois_result += "Expiration date: {}". format(py.get('expiration_data')) + '\n'
    whois_result += "Registrant: {}".format(py.get('registrant')) + '\n'
    whois_result += "Registrant Country: {}".format(py.get('registrant_country')) + '\n'
except:
    print(whois_result)


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
    print("[+] Latitude: {}".format(response['latitude']))
    print("[+] Longitude: {}".format(response['longitude']))
    print("[+] City: {}".format(response['city']))
    print("[+] State: {}".format(response['state']))
except:
    pass

#shodan
if ip:
    print("[+] Getting info form Shodan for IP {}".format(ip))
    api = shodan.Shodan("CNnZxGru644po9z9WDtWx8GMJqnTNoCX")
    try:
        results = api.search(ip)
        print("[+] Results found: {}".format(results['total']))
        for result in results['matches']:
            print("[+] IP: {}".format(result['ip_str']))
            print("[+] Data: \n{}".format(result['data']))
            print()
    except:
        print("[-] Shodan search error!!!")
