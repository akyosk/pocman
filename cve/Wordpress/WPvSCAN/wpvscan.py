#!/usr/bin/env python3
# Name: WPvSCAN
# https://github.com/cyb3rd3s/WPvSCAN
# Author: Roman Kulich @ 2020
# Version: v1.0.6
import bs4 as bs
import urllib.request
import os
import argparse
import requests
import sys

TGREEN =  '\033[32m' # Green Text
TWHITE = '\033[37m' # White text
TRED = '\033[31m' # White text
TYELL = '\033[33m' # Yellow text

print('''
 __          _______         _____  _____          _   _ 
 \ \        / /  __ \       / ____|/ ____|   /\   | \ | |
  \ \  /\  / /| |__) |_   _| (___ | |       /  \  |  \| |
   \ \/  \/ / |  ___/\ \ / /\___ \| |      / /\ \ | . ` |
    \  /\  /  | |     \ V / ____) | |____ / ____ \| |\  |
     \/  \/   |_|      \_/ |_____/ \_____/_/    \_\_| \_|                                                                                                                
v1.0.6
''')

response = requests.get('https://api.wordpress.org/core/version-check/1.7/')
json = response.json()

parser = argparse.ArgumentParser()
parser.add_argument("-t", help="target url", dest='domain')
args = parser.parse_args()

website = args.domain
if website is None:
    print(TRED + 'Missing target! ==>',TWHITE + TGREEN + 'Usage: python3 wpvscan.py -t target.com',TWHITE)
    print()
    sys.exit()

if website:
    if 'https://' in website: #Remove http or https to prevent errors
        website = website.strip('https://')
    elif 'http://' in website:
        website = website.strip('http://')

url = 'http://'+ website #Use http by default. If website uses https, request will change to https automatically
admin_url = url + '/wp-admin'

WPcheck = requests.get(admin_url) #Temporary solution how to determine, if website is running on WordPress :)

if WPcheck.status_code == 200:
    source = urllib.request.urlopen(url).read()
    soup = bs.BeautifulSoup(source,'lxml')
    WP_check = soup.find(attrs={'name' : 'generator'})
    WP_pars = WP_check['content']
    WP_name = WP_pars[0:9]
    WP_version = WP_pars[10:15]
    WP_now = str(json['offers'][0]['version'])
else:
    print(TRED,'Website is not running on WordPress!',TWHITE)

if website is None:
    print(TRED + "Missing target! ==>",TWHITE + TGREEN + "Usage: python3 wpvscan.py -t target.com",TWHITE)
    print("")
    sys.exit()
else:
    WPcheck = requests.get('https://'+ website + '/wp-admin') #Temporary solution how to determine, if website is running on WordPress :)

if WPcheck.status_code == 200:
    source = urllib.request.urlopen('https://'+ website).read()
    soup = bs.BeautifulSoup(source,'lxml')
    WP_check = soup.find(attrs={'name' : 'generator'})
    WP_pars = WP_check['content']
    WP_name = WP_pars[0:9]
    WP_version = WP_pars[10:15]
    WP_now = str(json['offers'][0]['version'])
else:
    print(TRED,"Website is not running on WordPress!",TWHITE)
    print("")
    sys.exit()

print(" ")
if WP_version == WP_now:
    print(TGREEN + "[+]",TWHITE + "Target website " + website + " is running on CMS " + WP_name + " of version " + TGREEN + WP_version,TWHITE)
else:
    print(TRED + "[!]",TWHITE + "Target website " + website + " is running on CMS " + WP_name + " of version " + TRED + WP_version,TWHITE)
print(TGREEN + "[+]",TWHITE + "Latest version is " + TGREEN + WP_now,TWHITE)

searchsploit = input("Do you want to use searchsploit to check exploits for this version? (y/n) ")
if searchsploit == "y":
    print(" ")
    print(os.system("searchsploit " + WP_pars))
else:
    print(TGREEN + "Finished",TWHITE)
