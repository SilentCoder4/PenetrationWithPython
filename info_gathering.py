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


